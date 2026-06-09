FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	WEB_ROOT=/srv/frontend \
	UI_PORT=80

WORKDIR /srv/frontend

COPY . /srv/frontend

RUN useradd --create-home --uid 10002 uiuser \
	&& chown -R uiuser:uiuser /srv/frontend

USER uiuser

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=5 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:80', timeout=3)"

CMD ["python", "scripts/serve_static.py"]
