# Senior Project

Automating Network Security Scans with Local LLMs
A Proof of Concept Using Ollama and Qwen3

# Current Challenges in Cybersecurity
Reliance on external AI services (e.g., cloud providers) leads to:
- Data exposure risks
- Vendor lock-in and dependency
- High costs for enterprise-grade solutions
- Limitations of traditional tools like Nmap:
- Manual command selection
- Limited customization
My Solution:
- Local AI Integration: Use Qwen3 hosted via Ollama to automate Nmap scans.

# Benefits: Control, cost efficiency, and data sovereignty
- The benefits lie with the in-house and cost-effective measures of using a company's own hardware to host AI
- Another major benefit is Data Loss Prevention. Many companies at this time are surrendering precious data to external corporate entities who own outsourced AI applications
- Some may worry that major AI cloud providers are leagues stronger in performance; this is quickly changing.
![image](https://github.com/user-attachments/assets/1fe5c7ad-3f06-4fde-944b-766dca166770)
![image](https://github.com/user-attachments/assets/0187256d-f095-41e6-84f4-7006d809ed1f)

# Project Overview
Key Objectives:
- Automate Nmap network scanning using AI-driven command selection
- Enable users to choose scan styles (Fast/Stealthy/Full) based on requirements
- Generate actionable reports with vulnerability analysis
Core Components:
- Ollama API: Host Qwen3:4b locally for secure, private processing
- Python Script: Orchestrate AI decisions and Nmap execution
- Nmap Application: The cybersecurity tool used for this proof-of-concept
- Report Generation: CSV + Markdown output for clarity and actionability

# System Architecture
- User Input: Scan style (Fast/Stealthy/Full)
- AI Decision Engine: Qwen3 selects optimal Nmap commands
- Nmap Execution: Scans host, gateway, and network range
- Data Aggregation: Combines scan results for analysis
- Report Generation: CSV (for data) + Markdown (for security insights)
Key Elements:
- Local hosting ensures data privacy
- AI-driven command selection improves efficiency
- Modular design allows scalability

# How It Works – Step-by-Step
Workflow Summary:
- Host Info Detection: Identify OS and IP address
- Network Range & Gateway: Determine CIDR and router IP
AI Command Selection:
- Scan style → AI chooses optimal Nmap commands (e.g., stealthy for low detection)
- Network Enumeration: Scan host, gateway, and network range
- Vulnerability Analysis: AI reviews scan data for risks
- Report Generation: CSV + Markdown output with remediation advice

# Technical Implementation
-  Python Script
-  Uses subprocess to execute Nmap commands
-  Leverages LangChain to interface with Ollama’s Qwen3:8b
-  AI Prompt Engineering
-  Structured prompts guide the model to select appropriate Nmap commands
-  Rationale extraction ensures transparency in decision-making
  Key Libraries/Tools
- langchain_ollama for AI interaction
- platform, subprocess for OS and command handling
- pandas, csv for report generation

# Results & Output: 01
![image](https://github.com/user-attachments/assets/5b599ae8-0631-4e46-9f9c-4a2cd10c7cdf)

# Results & Output 02
![image](https://github.com/user-attachments/assets/95d23f74-cfa9-4c51-af7c-9f4b61a1068f)

# Results & Output 03
![image](https://github.com/user-attachments/assets/1dbac805-e670-45de-a031-e885e4be3e74)

# Benefits of Local AI Integration
- Cost & Control Advantages
- Reduced Dependency on Cloud Providers: Avoid vendor lock-in and data exposure
- Cost Efficiency: Lower costs compared to enterprise AI solutions
- Customization: Tailor scanning logic and risk thresholds per organization
- Data Security
- All network data processed locally, minimizing the risk of leaks to external entities
- Compliance with regulations requiring data residency

# Risk Mitigation & Future Implications
Why Local AI Matters:
- Risk Scenario: If a cloud AI provider is compromised, organizations face double exposure (data + AI)
- Mitigation: Local hosting ensures control over both infrastructure and AI models
Future Potential:
- Expand to real-time threat detection
- Integrate with SIEM systems for automated incident response
- Support multi-LLM environments for specialized security tasks

# Challenges & Limitations
Current Constraints:
- Model size (Qwen3:4b) may limit complexity of vulnerability analysis
- Nmap command generation relies on pre-defined templates
- Requires manual input for scan styles and network ranges
Future Work:
- Enhance AI with more detailed vulnerability databases
- Add support for real-time scanning and anomaly detection
- Optimize model performance for larger networks

# Conclusion & Impact
A problem many companies will have in the future is the absolute reliance on outsourced AI for production and operational usage.  the outcome might be businesses  forever bound to AI corporations. More tangible risks are the possibility outsourced AI can be compromised, lose availability, or the company data is leaked which will lead to losses for both mutual parties.

A present solution lies with open-source AI. Companies should support AI alternatives that benefit all parties and not soley on a few AI providers.
