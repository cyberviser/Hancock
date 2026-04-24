FROM python:3.11-slim

LABEL maintainer="Johnny Watters <0ai@cyberviserai.com>"
LABEL description="Hancock — AI-powered cybersecurity agent maintained and licensed by Johnny Watters (0ai-Cyberviser)"

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY hancock_agent.py .
COPY hancock_constants.py .
COPY input_validator.py .
COPY orchestration_controller.py .
COPY langgraph/ langgraph/
COPY security/ security/
COPY sandbox/ sandbox/
COPY tools/ tools/
COPY collectors/ collectors/
COPY formatter/ formatter/
COPY monitoring/ monitoring/

# Expose API port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Run as non-root
RUN useradd -m hancock
USER hancock

CMD ["python", "hancock_agent.py", "--server", "--port", "5000"]
