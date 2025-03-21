import vt

#creating the client (vt_api)
vt_api = vt.Client("57413ddb6a6cc0657942fd811421c76d67cc3bee905626823ee31123c2d68f89")

# ex: checking the safety of a URL:
url_id = vt.url_id("http://www.virustotal.com")
url_results = vt_api.get_object("/urls/{}", url_id)

# checking how often a url is checked
url_results.times_submitted

# checking url analysis details 
url_results.last_analysis_stats
