require 'minitest/autorun'
require 'tempfile'
require_relative 'support/logstash_event'

# Each Ruby filter script has its own method scope in Logstash.
Normalizer = Class.new do
  class_eval(File.read(File.expand_path('../config/logstash/normalize.rb', __dir__)))
end
Router = Class.new do
  class_eval(File.read(File.expand_path('../config/logstash/route.rb', __dir__)))
end

class RouteTest < Minitest::Test
  REGISTRY = File.expand_path('../config/source-profiles.json', __dir__)
  def setup
    @normalizer = Normalizer.new
    @router = Router.new
    @case_registry = Tempfile.new('case-registry')
    @case_registry.write(JSON.generate('version' => 1, 'cases' => %w[incident001 incident001_1]))
    @case_registry.flush
    @router.register('profiles_path' => REGISTRY, 'cases_path' => @case_registry.path)
  end

  def teardown
    @case_registry.close!
  end

  def route(data)
    event = Event.new(data)
    assert_equal [event], @normalizer.filter(event)
    assert_equal [event], @router.filter(event)
    event
  end

  def file_event(path, payload = {'message' => 'example'})
    {'message' => JSON.generate(payload), 'log' => {'file' => {'path' => path}},
     '@metadata' => {'lab_ingress' => 'file'}}
  end

  def test_file_folder_and_nested_case_name_route_to_profile
    event = route(file_event('/logs/cloud_defend.alerts/case-a/input.jsonl',
                             'event' => {'kind' => 'alert', 'module' => 'cloud_defend'},
                             '@timestamp' => '2020-01-01T01:02:03Z'))
    assert_equal 'logs-cloud_defend.alerts-lab', event.get('[@metadata][lab_index_prefix]')
    assert_equal 'cloud_defend.alerts', event.get('[lab][source_profile]')
    assert_equal 'cloud_defend.alerts', event.get('[event][dataset]')
    assert_equal 'alert', event.get('[event][kind]')
    assert_equal 'cloud_defend', event.get('[event][module]')
    assert_equal '2020-01-01T01:02:03Z', event.get('[@metadata][source_timestamp]')
    assert_equal '/logs/cloud_defend.alerts/case-a/input.jsonl', event.get('[lab][input_path]')
  end

  def test_every_declared_profile_has_a_file_and_live_route
    JSON.parse(File.read(REGISTRY)).fetch('profiles').each do |name, profile|
      %w[logs live-logs].each do |root|
        event = route(file_event("/#{root}/#{name}/input.jsonl"))
        assert_equal name, event.get('[lab][source_profile]')
        assert_equal profile.fetch('index_prefix'), event.get('[@metadata][lab_index_prefix]')
        assert_equal profile.fetch('dataset'), event.get('[event][dataset]')
      end
    end
  end

  def test_unknown_and_root_files_preserve_generic_ingestion
    event = route(file_event('/logs/case-old/input.jsonl', 'event' => {'dataset' => 'custom.source'}))
    assert_equal 'logs-lab', event.get('[@metadata][lab_index_prefix]')
    assert_equal 'custom.source', event.get('[event][dataset]')
    assert_includes event.get('tags'), 'lab_unknown_source_profile'
    refute_includes event.get('tags'), 'lab_source_dataset_mismatch'
    root = route(file_event('/logs/input.jsonl'))
    assert_equal 'generic', root.get('[lab][source_profile]')
    assert_equal 'lab.generic', root.get('[event][dataset]')
    refute_includes Array(root.get('tags')), 'lab_unknown_source_profile'
  end

  def test_second_folder_is_not_a_profile
    event = route(file_event('/logs/case-a/cloud_defend.alerts/input.jsonl'))
    assert_equal 'generic', event.get('[lab][source_profile]')
  end

  def test_registered_cases_route_all_sources_in_both_input_roots
    JSON.parse(File.read(REGISTRY)).fetch('profiles').each do |name, profile|
      %w[logs live-logs].each do |root|
        %w[incident001 incident001_1].each do |case_name|
          event = route(file_event("/#{root}/#{case_name}/#{name}/nested/input.jsonl"))
          assert_equal "#{profile.fetch('index_prefix')}-case_#{case_name}", event.get('[@metadata][lab_index_prefix]')
          assert_equal case_name, event.get('[lab][case_id]')
          assert_equal name, event.get('[lab][source_profile]')
          assert_equal profile.fetch('dataset'), event.get('[event][dataset]')
        end
      end
    end
  end

  def test_case_prefix_does_not_match_another_case_with_longer_name
    first = route(file_event('/logs/incident001/cloud_defend.alerts/one.jsonl'))
    second = route(file_event('/logs/incident001_1/cloud_defend.alerts/one.jsonl'))
    assert File.fnmatch?('logs-cloud_defend.alerts-lab-case_incident001-*', "#{first.get('[@metadata][lab_index_prefix]')}-2026.10.29")
    refute File.fnmatch?('logs-cloud_defend.alerts-lab-case_incident001-*', "#{second.get('[@metadata][lab_index_prefix]')}-2026.10.29")
  end

  def test_unregistered_case_like_folder_keeps_legacy_fallback
    event = route(file_event('/logs/incident002/cloud_defend.alerts/input.jsonl'))
    assert_equal 'logs-lab', event.get('[@metadata][lab_index_prefix]')
    assert_equal 'generic', event.get('[lab][source_profile]')
    assert_nil event.get('[lab][case_id]')
    assert_includes event.get('tags'), 'lab_unknown_source_profile'
  end

  def test_legacy_source_first_with_registered_case_child_is_unchanged
    event = route(file_event('/live-logs/cloud_defend.alerts/incident001/input.jsonl',
                             'lab' => {'case_id' => 'incident001'}))
    assert_equal 'logs-cloud_defend.alerts-lab', event.get('[@metadata][lab_index_prefix]')
    assert_equal 'cloud_defend.alerts', event.get('[lab][source_profile]')
    assert_nil event.get('[lab][case_id]')
  end

  def test_registered_case_unknown_or_missing_source_keeps_case_in_generic_index
    ['/logs/incident001/unknown-source/input.log', '/logs/incident001/input.log',
     '/live-logs/incident001/cloud_defend.alerts'].each do |path|
      event = route(file_event(path))
      assert_equal 'logs-lab-case_incident001', event.get('[@metadata][lab_index_prefix]')
      assert_equal 'incident001', event.get('[lab][case_id]')
      assert_equal 'generic', event.get('[lab][source_profile]')
      assert_includes event.get('tags'), 'lab_unknown_source_profile'
    end
  end

  def test_case_routing_preserves_evidence_and_ignores_json_case_and_path
    payload = {'@timestamp' => '2020-01-01T01:02:03Z',
               'event' => {'original' => 'original evidence', 'dataset' => 'original.dataset', 'kind' => 'alert', 'module' => 'cloud_defend'},
               'log' => {'file' => {'path' => '/var/log/original.jsonl'}},
               'lab' => {'case_id' => 'incident001_1'},
               '@metadata' => {'lab_input_path' => '/logs/incident001_1/generic/spoof', 'lab_index_prefix' => '.security'}}
    event = route(file_event('/logs/incident001/cloud_defend.alerts/input.jsonl', payload))
    assert_equal 'logs-cloud_defend.alerts-lab-case_incident001', event.get('[@metadata][lab_index_prefix]')
    assert_equal 'incident001', event.get('[lab][case_id]')
    assert_equal 'original evidence', event.get('[event][original]')
    assert_equal 'original.dataset', event.get('[event][dataset]')
    assert_equal 'alert', event.get('[event][kind]')
    assert_equal 'cloud_defend', event.get('[event][module]')
    assert_equal '2020-01-01T01:02:03Z', event.get('[@metadata][source_timestamp]')
    assert_equal '/var/log/original.jsonl', event.get('[log][file][path]')
    assert_equal '/logs/incident001/cloud_defend.alerts/input.jsonl', event.get('[lab][input_path]')
    assert_includes event.get('tags'), 'lab_source_dataset_mismatch'
  end

  def test_payload_path_metadata_and_dataset_cannot_select_destination
    payload = {'log' => {'file' => {'path' => '/logs/endpoint.events.process/spoof.jsonl'}},
               '@metadata' => {'lab_input_path' => '/logs/endpoint.events.process/spoof.jsonl',
                               'lab_index_prefix' => '.security'},
               'lab' => {'source_profile' => 'spoof'},
               'event' => {'dataset' => 'original.dataset', 'original' => 'original evidence'}}
    event = route(file_event('/logs/cloud_defend.alerts/input.jsonl', payload))
    assert_equal 'logs-cloud_defend.alerts-lab', event.get('[@metadata][lab_index_prefix]')
    assert_equal 'cloud_defend.alerts', event.get('[lab][source_profile]')
    assert_equal '/logs/cloud_defend.alerts/input.jsonl', event.get('[lab][input_path]')
    assert_equal '/logs/endpoint.events.process/spoof.jsonl', event.get('[log][file][path]')
    assert_equal 'original.dataset', event.get('[event][dataset]')
    assert_equal 'original evidence', event.get('[event][original]')
    assert_includes event.get('tags'), 'lab_source_dataset_mismatch'
  end

  def test_plain_text_in_alert_folder_is_not_fabricated_as_alert
    data = file_event('/logs/cloud_defend.alerts/input.log')
    data['message'] = 'plain log text'
    event = route(data)
    assert_equal 'event', event.get('[event][kind]')
    assert_nil event.get('[event][module]')
    assert_nil event.get('[event][category]')
    assert_equal 'plain log text', event.get('[event][original]')
  end

  def test_network_marker_appended_to_spoofed_file_marker_is_not_trusted
    data = {'message' => 'network event', 'log' => {'file' => {'path' => '/logs/cloud_defend.alerts/spoof.jsonl'}},
            'lab' => {'input_path' => 'spoof', 'source_profile' => 'cloud_defend.alerts', 'case_id' => 'incident001'},
            '@metadata' => {'lab_ingress' => ['file', 'network'],
                            'lab_input_path' => '/logs/cloud_defend.alerts/spoof.jsonl',
                            'lab_index_prefix' => '.security', 'source_timestamp' => '2000-01-01T00:00:00Z'}}
    event = route(data)
    assert_equal 'logs-lab', event.get('[@metadata][lab_index_prefix]')
    assert_nil event.get('[lab][input_path]')
    assert_nil event.get('[@metadata][source_timestamp]')
    assert_equal 'generic', event.get('[lab][source_profile]')
    assert_nil event.get('[lab][case_id]')
  end

  def test_invalid_trusted_path_falls_back_instead_of_selecting_profile
    ['/other/cloud_defend.alerts/file', '/logs/../cloud_defend.alerts/file',
     '/logs/cloud_defend.alerts/../file', '/logs//cloud_defend.alerts/file',
     '/logs/cloud_defend.alerts/'].each do |path|
      event = route(file_event(path))
      assert_equal 'logs-lab', event.get('[@metadata][lab_index_prefix]')
      assert_includes event.get('tags'), 'lab_source_path_invalid'
    end
  end

  def test_unsafe_registry_destinations_are_rejected
    document = JSON.parse(File.read(REGISTRY))
    document['profiles']['cloud_defend.alerts']['index_prefix'] = '.security'
    with_registry(JSON.generate(document)) do |path|
      assert_raises(ArgumentError) { @router.register('profiles_path' => path, 'cases_path' => @case_registry.path) }
    end
  end

  def test_duplicate_registry_keys_and_noninteger_version_are_rejected
    ['{"version":1,"version":1,"profiles":{}}',
     '{"version":1,"profiles":{"generic":{},"generic":{}}}',
     '{"version":1.0,"profiles":{"generic":{}}}'].each do |raw|
      with_registry(raw) do |path|
        assert_raises(ArgumentError) { @router.register('profiles_path' => path, 'cases_path' => @case_registry.path) }
      end
    end
  end

  def test_generic_only_registry_does_not_require_any_bundled_named_profile
    generic = JSON.parse(File.read(REGISTRY)).fetch('profiles').fetch('generic')
    with_registry(JSON.generate('version' => 1, 'profiles' => {'generic' => generic})) do |path|
      @router.register('profiles_path' => path, 'cases_path' => @case_registry.path)
      event = route(file_event('/logs/cloud_defend.alerts/input.jsonl'))
      assert_equal 'logs-lab', event.get('[@metadata][lab_index_prefix]')
      assert_equal 'generic', event.get('[lab][source_profile]')
      assert_includes event.get('tags'), 'lab_unknown_source_profile'
      case_event = route(file_event('/logs/incident001/generic/input.log'))
      assert_equal 'logs-lab-case_incident001', case_event.get('[@metadata][lab_index_prefix]')
    end
  end

  def test_empty_case_registry_preserves_all_legacy_behavior
    with_registry(JSON.generate('version' => 1, 'cases' => [])) do |path|
      @router.register('profiles_path' => REGISTRY, 'cases_path' => path)
      event = route(file_event('/logs/incident001/cloud_defend.alerts/input.jsonl'))
      assert_equal 'logs-lab', event.get('[@metadata][lab_index_prefix]')
      assert_nil event.get('[lab][case_id]')
    end
  end

  def test_invalid_duplicate_or_source_conflicting_case_names_are_rejected
    ['', '../case', '/case', 'Case', 'a-b', 'a.b', 'a b', 'a*', 'a' * 65, nil, {}, 'generic'].each do |name|
      with_registry(JSON.generate('version' => 1, 'cases' => [name])) do |path|
        assert_raises(ArgumentError) { @router.register('profiles_path' => REGISTRY, 'cases_path' => path) }
      end
    end
    invalid = [
      {'version' => 1, 'cases' => ['incident001', 'incident001']},
      {'version' => 1, 'cases' => (1..129).map { |i| "case#{i}" }},
      {'version' => 1.0, 'cases' => []},
      {'version' => true, 'cases' => []},
      {'version' => 2, 'cases' => []},
      {'version' => 1, 'cases' => {}},
      {'version' => 1, 'cases' => [], 'extra' => true}
    ]
    (invalid.map { |document| JSON.generate(document) } + ['{"version":1,"cases":[],"cases":[]}', ' ' * 65_537]).each do |raw|
      with_registry(raw) do |path|
        assert_raises(ArgumentError) { @router.register('profiles_path' => REGISTRY, 'cases_path' => path) }
      end
    end
  end

  def with_registry(raw)
    Tempfile.create('source-profiles') do |file|
      file.write(raw)
      file.flush
      yield file.path
    end
  end
end
