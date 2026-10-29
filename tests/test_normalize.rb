require 'minitest/autorun'
require_relative '../config/logstash/normalize'

# Emulates only the documented Event field API; pipeline parsing is checked
# separately with the actual Logstash image, not inferred from this stub.
class Event
  attr_reader :data
  def initialize(data)
    @data = data
  end
  def path(key)
    key.start_with?('[') ? key.scan(/\[([^\]]+)\]/).flatten : [key]
  end
  def get(key)
    path(key).reduce(@data) { |value, part| value.is_a?(Hash) ? value[part] : nil }
  end
  def set(key, value)
    parts = path(key)
    parent = parts[0...-1].reduce(@data) { |hash, part| hash[part] ||= {} }
    parent[parts[-1]] = value
  end
  def remove(key)
    @data.delete(key)
  end
  def tag(value)
    @data['tags'] ||= []
    @data['tags'] << value
  end
end

class NormalizeTest < Minitest::Test
  def normalize(data)
    event = Event.new(data)
    assert_equal [event], filter(event)
    event
  end
  def test_plain_text_keeps_original_and_path
    event = normalize('message' => 'sshd: login failed', 'log' => {'file' => {'path' => '/logs/auth.log'}})
    assert_equal 'sshd: login failed', event.get('[event][original]')
    assert_equal '/logs/auth.log', event.get('[log][file][path]')
    assert_equal 'lab.generic', event.get('[event][dataset]')
  end
  def test_ecs_json_preserves_fields_and_routes_timestamp_to_date_filter
    raw = JSON.generate('@timestamp' => '2026-10-29T00:00:00Z', 'message' => 'login',
                        'event' => {'category' => ['authentication'], 'outcome' => 'failure'},
                        'source' => {'ip' => '192.0.2.10'}, 'host' => {'name' => 'test'})
    event = normalize('message' => raw)
    assert_equal ['authentication'], event.get('[event][category]')
    assert_equal '192.0.2.10', event.get('[source][ip]')
    assert_equal '2026-10-29T00:00:00Z', event.get('[@metadata][source_timestamp]')
    assert_equal raw, event.get('[event][original]')
  end
  def test_malformed_json_is_searchable_and_marked
    event = normalize('message' => '{broken')
    assert_includes event.get('tags'), 'lab_json_parse_failure'
    assert_equal '{broken', event.get('[event][original]')
  end
  def test_array_json_remains_one_raw_event
    event = normalize('message' => '[1,2]')
    assert_includes event.get('tags'), 'lab_json_nonobject'
    assert_equal '[1,2]', event.get('message')
  end
  def test_source_cannot_overwrite_control_metadata
    event = normalize('message' => JSON.generate('@metadata' => {'source_timestamp' => 'bad'},
                                                 '[event][original]' => 'bad', 'lab' => 'bad'))
    assert_nil event.get('[@metadata][source_timestamp]')
    assert_nil event.get('lab')
  end
  def test_scalar_reserved_ecs_fields_are_retained_without_mapping_conflict
    event = normalize('message' => JSON.generate('event' => 'login', 'host' => 'example'))
    assert_equal 'login', event.get('[lab][unmapped][event]')
    assert_equal 'example', event.get('[lab][unmapped][host]')
    assert_equal 'event', event.get('[event][kind]')
  end
  def test_structured_beats_event_does_not_require_message
    event = normalize('event' => {'dataset' => 'system.auth'}, 'host' => {'name' => 'test'})
    assert_equal 'system.auth', event.get('[event][dataset]')
    assert_nil event.get('[event][original]')
  end
  def test_beats_raw_evidence_is_not_overwritten_by_normalized_message
    original = 'Oct 29 sshd[123]: failed login from 192.0.2.10'
    event = normalize('message' => 'Failed login for alice', 'event' => {'original' => original})
    assert_equal original, event.get('[event][original]')
    assert_equal 'Failed login for alice', event.get('message')
  end
  def test_json_embedded_original_evidence_is_preserved
    raw = JSON.generate('message' => 'Failed login for alice', 'event' => {'original' => 'raw source record'})
    event = normalize('message' => raw)
    assert_equal 'raw source record', event.get('[event][original]')
    assert_equal 'Failed login for alice', event.get('message')
  end
  def test_tags_are_merged
    event = normalize('message' => '{"tags":["source-tag"]}', 'tags' => ['input-tag'])
    assert_equal ['input-tag', 'source-tag'], event.get('tags')
  end
  def test_structured_message_does_not_conflict_with_text_mapping
    raw = '{"message":{"text":"hello"}}'
    event = normalize('message' => raw)
    assert_equal raw, event.get('message')
    assert_equal 'hello', event.get('[lab][unmapped][message]')['text']
  end
  def test_structured_input_scalar_ecs_is_normalized
    event = normalize('ecs' => 'legacy', 'message' => 'example')
    assert_equal 'legacy', event.get('[lab][unmapped][ecs]')
    assert_equal '8.11.0', event.get('[ecs][version]')
  end
end
