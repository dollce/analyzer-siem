require 'json'

class LabProfileObject < Hash
  def []=(key, value)
    raise ArgumentError, "Duplicate source profile key: #{key}" if key?(key)
    super
  end
end

# The same checked registry supplies bootstrap permissions and index templates.
# Only fixed lab-owned prefixes are accepted; event content never chooses one.
def register(params)
  path = params.fetch('profiles_path', '/usr/share/logstash/config/source-profiles.json')
  raw = File.open(path, 'rb') { |source| source.read(65_537) }
  raise ArgumentError, 'Source profile registry is too large' if raw.bytesize > 65_536
  document = JSON.parse(raw, object_class: LabProfileObject)
  profiles = document.is_a?(Hash) ? document['profiles'] : nil
  unless document.is_a?(Hash) && document.keys.sort == %w[profiles version] &&
         document['version'].is_a?(Integer) && document['version'] == 1 && profiles.is_a?(Hash) &&
         profiles.size.between?(1, 64) && profiles.key?('generic')
    raise ArgumentError, 'Expected source profile registry version 1 with generic profile'
  end
  @profiles = profiles.each_with_object({}) do |(name, profile), result|
    unless name.match?(/\A[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*\z/) && name.length <= 100 && profile.is_a?(Hash)
      raise ArgumentError, "Invalid source profile: #{name}"
    end
    prefix = name == 'generic' ? 'logs-lab' : "logs-#{name}-lab"
    dataset = name == 'generic' ? 'lab.generic' : name
    unless profile['index_prefix'] == prefix && profile['dataset'] == dataset
      raise ArgumentError, "Source profile #{name} must use its own fixed lab index and dataset"
    end
    result[name] = {'index_prefix' => prefix.freeze, 'dataset' => dataset.freeze}.freeze
  end.freeze
end

def filter(event)
  # normalize.rb sets this from trusted file input metadata BEFORE JSON parsing.
  path = event.get('[@metadata][lab_input_path]')
  profile_name = 'generic'
  if path.is_a?(String)
    event.set('[lab][input_path]', path)
    parts = path.split('/', -1)
    if parts.length >= 3 && parts[0] == '' && %w[logs live-logs].include?(parts[1]) &&
       parts[2..-1].all? { |part| !['', '.', '..'].include?(part) && !part.include?("\0") }
      if parts.length > 3
        folder = parts[2]
        if @profiles.key?(folder)
          profile_name = folder
        else
          event.tag('lab_unknown_source_profile')
        end
      end
    else
      event.tag('lab_source_path_invalid')
    end
  else
    event.remove('[lab][input_path]')
  end
  profile = @profiles.fetch(profile_name)
  event.set('[@metadata][lab_index_prefix]', profile.fetch('index_prefix'))
  event.set('[lab][source_profile]', profile_name)
  dataset = event.get('[event][dataset]')
  if dataset.nil?
    event.set('[event][dataset]', profile.fetch('dataset'))
  elsif profile_name != 'generic' && dataset != profile.fetch('dataset')
    # Keep the source field as evidence. This flag explains why a dataset-based
    # rule might not match even though the destination index is compatible.
    event.tag('lab_source_dataset_mismatch')
  end
  [event]
end

if respond_to?(:test)
  # Tests must remain valid when an operator keeps only generic or substitutes
  # their own profiles. Pick one configured folder instead of requiring a demo.
  dsl_profiles = JSON.parse(File.read('/usr/share/logstash/config/source-profiles.json')).fetch('profiles')
  dsl_name = (dsl_profiles.keys - ['generic']).first || 'generic'
  dsl_profile = dsl_profiles.fetch(dsl_name)
  test 'configured folder selects its lab index without manufacturing alerts' do
    parameters { {} }
    in_event do
      {'message' => 'plain source text', '@metadata' => {'lab_input_path' => "/logs/#{dsl_name}/case-a/input.log"}}
    end
    expect('source routing only') do |events|
      event = events[0]
      event.get('[@metadata][lab_index_prefix]') == dsl_profile.fetch('index_prefix') &&
        event.get('[lab][source_profile]') == dsl_name &&
        event.get('[event][dataset]') == dsl_profile.fetch('dataset') &&
        event.get('[event][kind]').nil? && event.get('[event][module]').nil?
    end
  end

  test 'unknown folder keeps data in the generic index' do
    parameters { {} }
    in_event { {'@metadata' => {'lab_input_path' => '/logs/unknown-source/input.log'}} }
    expect('generic with diagnostic') do |events|
      events[0].get('[@metadata][lab_index_prefix]') == 'logs-lab' &&
        events[0].get('tags').include?('lab_unknown_source_profile')
    end
  end

  test 'network input cannot select output from sender fields' do
    parameters { {} }
    in_event do
      {'@metadata' => {'lab_index_prefix' => '.security'}, 'log' => {'file' => {'path' => '/logs/cloud_defend.alerts/fake.json'}}}
    end
    expect('fixed generic destination') do |events|
      events[0].get('[@metadata][lab_index_prefix]') == 'logs-lab' &&
        events[0].get('[lab][input_path]').nil?
    end
  end
end
