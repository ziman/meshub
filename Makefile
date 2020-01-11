all: .ts-typecheck

.ts-typecheck: *.py mypy.ini
	python3 -m mypy client.py hub.py generate_fernet_key.py
	touch .ts-typecheck

clean:
	-rm -f .ts-typecheck
