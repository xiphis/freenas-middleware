stop_service:
	systemctl stop middlewared

start_service:
	systemctl daemon-reload
	systemctl restart middlewared

clean:
	# deb packages install to a different location
	# compared to pip. This removes any remnants
	# of middlewared so we don't have situation of
	# two "middlewared" packages being on disk at
	# same time.
	find /usr -type d \( -path "*/dist-packages/middlewared" -o -path "*/site-packages/middlewared" \) 2>/dev/null | xargs -r rm -rf

install:
	DEB_PYTHON_INSTALL_LAYOUT=deb pip install --prefix /usr --upgrade --force-reinstall --no-build-isolation --break-system-packages --root-user-action=ignore .
	cp ./debian/middlewared.service /usr/lib/systemd/system/middlewared.service

install_test:
	bash install-dev-tools
	@python3 -c "import sys; v=sys.version_info; print(f'Python {v.major}.{v.minor}.{v.micro}'); sys.exit(0 if v[:2] < (3,12) else 1)" && \
		DEB_PYTHON_INSTALL_LAYOUT=deb pip install --prefix /usr --upgrade --force-reinstall --no-build-isolation --break-system-packages --root-user-action=ignore . || \
		echo "Skipping pip install - Python version >= 3.12"

migrate:
	migrate

reinstall: stop_service clean install migrate start_service

# this is to be called in github actions running in a container (no systemd (pid 1))
# so it's the same as `reinstall` but without the start/stop{_service} and migrate calls
# FIXME: install_client is no more
reinstall_container: clean install install_test
