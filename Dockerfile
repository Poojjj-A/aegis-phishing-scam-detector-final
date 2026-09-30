FROM python:3.12-slim

WORKDIR /srv/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Train the model at build time so the container starts instantly
# (also happens automatically on first request if this is skipped).
RUN python generate_dataset.py && python train_model.py

EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app.main:app", "--workers", "2", "--timeout", "60"]
