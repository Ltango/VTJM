# VTJM
Virus Total, Jira, and Mimecast come together to help automate the resolution of phishing tickets

This script integrates with Jira, searches for URLs in the tickets, checks to see if they have already been blocked using Mimecast, and gets Virus Total results on the other URLs embedded in the Jira ticket.  The results are posted as an internal comment in Jira for the specified ticket.  If the URL has already been blocked an no potentially dangerous links otherwise have been found we will automatically resolve the ticket and assign it to whomever signed in using the script - along with an automated comment seen by the assigner in Jira about the response.

