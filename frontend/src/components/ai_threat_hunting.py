@app.route("/predict_behavior", methods=["POST"])
def predict_behavior():
    data = request.get_json()
    threat_description = data.get("threat_description", "")

    if not threat_description:
        return jsonify({"error": "Missing threat_description"}), 400

    prediction = predict_threat_behavior(threat_description)
    return jsonify({"prediction": prediction})


def predict_threat_behavior(threat_description):
    # Format the prompt into a question-like statement
    prompt = (
        f"Analyze the following security threat and predict possible next attack vectors:\n"
        f"{threat_description}"
    )

    headers = {
        "Authorization": f"Bearer {os.getenv('HUGGING_FACE_KEY')}",
        "Content-Type": "application/json"
    }

    payload = {
        "inputs": prompt
    }

    try:
        response = requests.post(os.getenv("HUGGING_FACE_URL"), headers=headers, json=payload)

        if response.status_code != 200:
            return f"Hugging Face API error: {response.status_code}"

        result = response.json()

        # Handle both classification and text-generation responses
        if isinstance(result, dict) and "generated_text" in result:
            return result["generated_text"]
        elif isinstance(result, list) and "generated_text" in result[0]:
            return result[0]["generated_text"]
        else:
            return "Unexpected response format from Hugging Face."
    except Exception as e:
        return f"Error contacting Hugging Face API: {str(e)}"