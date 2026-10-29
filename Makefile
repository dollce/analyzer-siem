.PHONY: init up down destroy status check check-logstash smoke sync-labs sources
init up down status check smoke sync-labs sources:
	python3 builder.py $@
destroy:
	python3 builder.py destroy --yes
check-logstash:
	bash scripts/check_logstash.sh
