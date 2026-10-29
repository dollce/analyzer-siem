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
  cases_path = params.fetch('cases_path', '/cases/registry.json')
  if File.symlink?(cases_path) || !File.file?(cases_path)
    raise ArgumentError, 'Expected an ordinary case registry file'
  end
  raw_cases = File.open(cases_path, 'rb') { |source| source.read(65_537) }
  raise ArgumentError, 'Case registry is too large' if raw_cases.bytesize > 65_536
  case_document = JSON.parse(raw_cases, object_class: LabProfileObject)
  cases = case_document.is_a?(Hash) ? case_document['cases'] : nil
  unless case_document.is_a?(Hash) && case_document.keys.sort == %w[cases version] &&
         case_document['version'].is_a?(Integer) && case_document['version'] == 1 &&
         cases.is_a?(Array) && cases.size <= 128
    raise ArgumentError, 'Expected case registry version 1 with at most 128 cases'
  end
  @cases = cases.each_with_object({}) do |name, result|
    unless name.is_a?(String) && name.match?(/\A[a-z][a-z0-9_]{0,63}\z/) &&
           !@profiles.key?(name) && !result.key?(name)
      raise ArgumentError, "Invalid, duplicate or source-conflicting case: #{name}"
    end
    result[name.freeze] = true
  end.freeze
end

def filter(event)
  # normalize.rb sets this from trusted file input metadata BEFORE JSON parsing.
  path = event.get('[@metadata][lab_input_path]')
  profile_name = 'generic'
  case_name = nil
  # Case membership comes only from a registered, trusted local input path.
  event.remove('[lab][case_id]')
  if path.is_a?(String)
    event.set('[lab][input_path]', path)
    parts = path.split('/', -1)
    if parts.length >= 3 && parts[0] == '' && %w[logs live-logs].include?(parts[1]) &&
       parts[2..-1].all? { |part| !['', '.', '..'].include?(part) && !part.include?("\0") }
      if parts.length > 3
        folder = parts[2]
        if @profiles.key?(folder)
          # Preserve legacy source-first paths, including nested case-like names.
          profile_name = folder
        elsif @cases.key?(folder)
          case_name = folder
          if parts.length > 4 && @profiles.key?(parts[3])
            profile_name = parts[3]
          else
            event.tag('lab_unknown_source_profile')
          end
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
  prefix = profile.fetch('index_prefix')
  if case_name
    prefix = "#{prefix}-case_#{case_name}"
    event.set('[lab][case_id]', case_name)
  end
  event.set('[@metadata][lab_index_prefix]', prefix)
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
  dsl_cases = JSON.parse(File.read('/cases/registry.json')).fetch('cases')
  # An empty registry is normal. Keep the tests executable with either no cases
  # or a caller-provided registry, without creating runtime state or input files.
  dsl_unregistered = (1..200).map { |number| "routingcheck_#{number}" }.find do |name|
    !dsl_profiles.key?(name) && !dsl_cases.include?(name)
  end
  dsl_case = dsl_cases.first || dsl_unregistered
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
      {'@metadata' => {'lab_index_prefix' => '.security'}, 'lab' => {'case_id' => 'spoof'},
       'log' => {'file' => {'path' => '/logs/cloud_defend.alerts/fake.json'}}}
    end
    expect('fixed generic destination') do |events|
      events[0].get('[@metadata][lab_index_prefix]') == 'logs-lab' &&
        events[0].get('[lab][input_path]').nil? && events[0].get('[lab][case_id]').nil?
    end
  end

  test 'case-first paths route only when explicitly registered' do
    parameters { {} }
    in_event do
      {'@metadata' => {'lab_input_path' => "/logs/#{dsl_case}/#{dsl_name}/input.jsonl"},
       'lab' => {'case_id' => 'spoof'}}
    end
    expect('registered case is isolated and unregistered path stays generic') do |events|
      event = events[0]
      if dsl_cases.include?(dsl_case)
        event.get('[@metadata][lab_index_prefix]') == "#{dsl_profile.fetch('index_prefix')}-case_#{dsl_case}" &&
          event.get('[lab][case_id]') == dsl_case && event.get('[lab][source_profile]') == dsl_name
      else
        event.get('[@metadata][lab_index_prefix]') == 'logs-lab' &&
          event.get('[lab][case_id]').nil? && event.get('tags').include?('lab_unknown_source_profile')
      end
    end
  end

  test 'legacy source-first path remains unchanged under a case-like child' do
    parameters { {} }
    in_event do
      {'@metadata' => {'lab_input_path' => "/live-logs/#{dsl_name}/#{dsl_case}/input.jsonl"},
       'lab' => {'case_id' => dsl_case}}
    end
    expect('no implicit case conversion') do |events|
      events[0].get('[@metadata][lab_index_prefix]') == dsl_profile.fetch('index_prefix') &&
        events[0].get('[lab][case_id]').nil?
    end
  end
end
