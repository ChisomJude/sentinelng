FROM apify/actor-python:3.11

COPY requirements.txt ./

RUN echo "Python version:" \
 && python --version \
 && echo "Installing dependencies:" \
 && pip install -r requirements.txt \
 && echo "All installed Python packages:" \
 && pip freeze

COPY . ./

CMD ["python3", "-m", "src"]
