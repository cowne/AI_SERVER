def preprocess_dns(data: dict):
    fields = ["subdomain_length", "upper", "lower", "numeric", "entropy","special","labels","labels_max","labels_average","longest_word","len","subdomain"]
    return [float(data.get(f, 0)) for f in fields]
