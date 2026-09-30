web: gunicorn -b 0.0.0.0:$PORT app.main:app
release: python generate_dataset.py && python train_model.py
