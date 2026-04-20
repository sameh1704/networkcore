def predict_capacity(traffic):

    growth = traffic[-1] - traffic[0]

    if growth > 300000000:
        return "Upgrade link capacity soon"

    return "Capacity OK"