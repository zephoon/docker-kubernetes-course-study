FROM python:3.11

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Install dependencies
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 6000
EXPOSE 6000

# Start Flask app
CMD ["flask", "run", "--port=6000"]