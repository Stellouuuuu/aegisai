FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY chatbot /app/chatbot
EXPOSE 8001
CMD ["uvicorn", "chatbot.app:app", "--host", "0.0.0.0", "--port", "8001"]
