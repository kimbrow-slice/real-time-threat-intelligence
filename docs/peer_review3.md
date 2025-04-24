**Mohamed Elgasim Project Peer Review**   


**Jeff Kimbrow**


Jeff played a crucial role in turning our ideas into a functioning system. He developed a smart risk scoring engine that took time decay into account so we wouldn’t be overwhelmed by outdated alerts. He also integrated multiple intelligence sources including EPSS, CVE, and OSV to give us a more complete picture of threats.
One of his standout achievements was building an AI dashboard using Hugging Face. It translated complex data into visuals that even non-technical team members could understand and work with.
Jeff also reorganized our GitHub repositories, which really streamlined our workflow. The improved structure helped the whole team collaborate more effectively and made documentation much easier to manage.

**Kenneth Kakie**

Kenneth focused on bringing order to messy threat intelligence data. He started by setting up solid data ingestion pipelines, then built routines to clean and standardize the incoming information from various sources.
He followed that by creating logic that connected those threats directly to our vulnerabilities, making the data much more actionable. His work on AI-based threat hunting tools allowed us to detect possible risks ahead of time instead of waiting for them to appear in the usual feeds.
His front-end integrations also played a key role in making raw threat data usable for analysts. Even when pushed beyond expected data loads, his components performed smoothly under pressure.

**Hashim Abdulla**

Hashim shaped the security foundation of our application. He embedded logic that aligned with CSF and RMF frameworks inside the mitigation system, defining how risks would trigger responses.
He built the alerting structure in alerts.py which made it easier for me to finish integrating the full alerting logic. In addition, he developed cost benefit models in cba_analysis.py that helped us decide which vulnerabilities to address first by weighing their potential impact against available resources.
His work in security_audit.md tied everything together by outlining weaknesses, documenting audit trails, and offering control recommendations. Hashim’s contributions gave us a clear and strategic path to follow, allowing the team to focus on the most pressing threats with a balanced and risk-aware approach.
