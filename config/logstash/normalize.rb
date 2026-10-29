require 'json'

# Keep raw evidence and accept either line-oriented text or one ECS JSON object
# per line. This is not a vendor-specific parser for every possible log format.
def filter(event)
  # Capture the local file plugin's path before merging JSON. Network inputs
  # append their own marker and can never supply the exact trusted file marker.
  # Always reset these fields: a Beats sender can include arbitrary metadata.
  input_path = event.get('[@metadata][lab_ingress]') == 'file' ? event.get('[log][file][path]') : nil
  event.set('[@metadata][lab_input_path]', input_path.is_a?(String) ? input_path : nil)
  event.set('[@metadata][lab_index_prefix]', 'logs-lab')
  event.remove('[@metadata][source_timestamp]')
  objects = %w[event host source destination user process file network observer agent log ecs rule related threat cloud container data_stream]
  original = event.get('message')
  file_path = event.get('[log][file][path]')
  unless event.get('lab').nil? || event.get('lab').is_a?(Hash)
    value = event.remove('lab')
    event.set('[lab][unmapped][lab]', value)
  end
  if original.is_a?(String) && ['{', '['].include?(original.lstrip[0])
    begin
      parsed = JSON.parse(original)
      if parsed.is_a?(Hash)
        parsed.each do |key, value|
          # Input cannot overwrite Logstash routing/control metadata.
          next if key.start_with?('@') && key != '@timestamp'
          next if key.include?('[') || key.include?(']')
          next if key == 'lab'
          if key == '@timestamp'
            event.set('[@metadata][source_timestamp]', value.to_s)
          elsif key == 'tags'
            event.set('tags', (Array(event.get('tags')) + Array(value)).map(&:to_s).uniq)
          elsif objects.include?(key) && !value.is_a?(Hash)
            event.set("[lab][unmapped][#{key}]", value)
            event.tag('lab_non_ecs_field')
          else
            event.set(key, value)
          end
        end
      else
        event.tag('lab_json_nonobject')
      end
    rescue JSON::ParserError
      event.tag('lab_json_parse_failure')
    end
  end
  # Beats can supply an already structured event without a message.
  objects.each do |key|
    value = event.get(key)
    unless value.nil? || value.is_a?(Hash)
      event.remove(key)
      event.set("[lab][unmapped][#{key}]", value)
      event.tag('lab_non_ecs_field')
    end
  end
  unless event.get('message').nil? || event.get('message').is_a?(String)
    value = event.remove('message')
    event.set('[lab][unmapped][message]', value)
    event.set('message', original.is_a?(String) ? original : JSON.generate(value))
  end
  if event.get('[event][original]').nil? && original.is_a?(String)
    event.set('[event][original]', original)
  end
  event.set('[event][kind]', 'event') unless event.get('[event][kind]')
  event.set('[ecs][version]', '8.11.0') unless event.get('[ecs][version]')
  event.set('[log][file][path]', file_path) if file_path && !event.get('[log][file][path]')
  [event]
end

# Logstash's Ruby filter DSL executes these against real LogStash::Event objects
# during --config.test_and_exit. The standalone Ruby suite skips this block.
if respond_to?(:test)
  test 'ECS JSON preserves evidence and source fields' do
    in_event do
      {'message' => '{"@timestamp":"2026-10-29T00:00:00Z","event":{"category":["authentication"]},"source":{"ip":"192.0.2.10"}}'}
    end
    expect('one ECS event with intact original') do |events|
      events.size == 1 &&
        events[0].get('[source][ip]') == '192.0.2.10' &&
        events[0].get('[event][category]') == ['authentication'] &&
        events[0].get('[@metadata][source_timestamp]') == '2026-10-29T00:00:00Z' &&
        events[0].get('[event][original]').start_with?('{')
    end
  end

  test 'structured message is preserved without text mapping conflict' do
    in_event { {'message' => '{"message":{"text":"hello"},"event":"example"}'} }
    expect('message remains text and scalar event is preserved') do |events|
      events[0].get('message').is_a?(String) &&
        events[0].get('[lab][unmapped][message]')['text'] == 'hello' &&
        events[0].get('[lab][unmapped][event]') == 'example'
    end
  end

  test 'existing raw evidence survives a normalized Beats message' do
    in_event do
      {'message' => 'Failed login for alice', 'event' => {'original' => 'Oct 29 sshd[123]: failed login from 192.0.2.10'}}
    end
    expect('original evidence is not replaced by the normalized message') do |events|
      events[0].get('[event][original]') == 'Oct 29 sshd[123]: failed login from 192.0.2.10' &&
        events[0].get('message') == 'Failed login for alice'
    end
  end

  test 'trusted local input path survives a different JSON source path' do
    in_event do
      {'message' => '{"log":{"file":{"path":"/var/log/source.log"}},"@metadata":{"lab_input_path":"spoof"}}',
       'log' => {'file' => {'path' => '/logs/cloud_defend.alerts/case-a/input.jsonl'}},
       '@metadata' => {'lab_ingress' => 'file'}}
    end
    expect('local route path and original source path are both retained') do |events|
      events[0].get('[@metadata][lab_input_path]') == '/logs/cloud_defend.alerts/case-a/input.jsonl' &&
        events[0].get('[log][file][path]') == '/var/log/source.log'
    end
  end

  test 'network ingress resets routing fields supplied by a sender' do
    in_event do
      {'message' => 'network source', 'log' => {'file' => {'path' => '/logs/cloud_defend.alerts/spoof.jsonl'}},
       '@metadata' => {'lab_ingress' => ['file', 'network'], 'lab_input_path' => 'spoof', 'lab_index_prefix' => '.security'}}
    end
    expect('no trusted file path is captured') do |events|
      events[0].get('[@metadata][lab_input_path]').nil? &&
        events[0].get('[@metadata][lab_index_prefix]') == 'logs-lab'
    end
  end
end
