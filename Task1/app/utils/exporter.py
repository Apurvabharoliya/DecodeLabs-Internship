import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor

def export_to_pdf(password: str, results: dict, filepath: str):
    """
    Exports the password analysis report to a PDF file.
    """
    c = canvas.Canvas(filepath, pagesize=letter)
    width, height = letter
    
    # Title
    c.setFont("Helvetica-Bold", 24)
    c.setFillColor(HexColor("#00ffcc"))
    c.rect(0, height - 60, width, 60, fill=1)
    
    c.setFillColor(HexColor("#111111"))
    c.drawString(50, height - 40, "Password Security Audit Report")
    
    # Meta info
    c.setFont("Helvetica", 12)
    c.setFillColor(HexColor("#333333"))
    c.drawString(50, height - 90, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Stats
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 130, "Analysis Results:")
    
    c.setFont("Helvetica", 12)
    c.drawString(70, height - 160, f"Strength: {results['strength']}")
    c.drawString(70, height - 180, f"Score: {results['score']} / 5")
    c.drawString(70, height - 200, f"Entropy: {results['entropy']} bits")
    c.drawString(70, height - 220, f"Est. Crack Time: {results['crack_time']['display']}")
    
    # Feedback
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 260, "Security Feedback:")
    
    c.setFont("Helvetica", 12)
    y_pos = height - 290
    for item in results['feedback']:
        c.drawString(70, y_pos, f"- {item}")
        y_pos -= 20
        
    c.save()
