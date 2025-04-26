from fpdf import FPDF
import datetime
from tkinter import filedialog, messagebox
import tempfile, webbrowser

class PDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "", 10)
        report_date = getattr(self, 'report_date', datetime.datetime.now().strftime('%Y-%m-%d'))
        self.cell(95, 5, f"Report Date: {report_date}", border=0, align="L")
        self.cell(95, 5, f"Criticality: {getattr(self, 'criticality', 'N/A')}", border=0, align="R")
        self.ln(8)
        self.set_draw_color(200, 200, 200)
        self.set_line_width(0.5)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-20)
        self.set_font("Helvetica", "", 10)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), self.w - 10, self.get_y())
        self.ln(2)
        self.cell(95, 5, f"Report Number: {getattr(self, 'report_number', 'N/A')}", border=0, align="L")
        self.cell(95, 5, f"TLP/Company Sensitivity Marking: {getattr(self, 'sensitivity', 'N/A')}", border=0, align="R")
        self.ln(5)
        self.cell(0, 5, f"Page {self.page_no()} of {{nb}}", align="C")

class PDFreport_generator:
    @staticmethod
    def _build_pdf(data):
        pdf = PDF()
        pdf.alias_nb_pages()
        pdf.report_title = data["Report Title"]
        pdf.criticality = data.get("Criticality", "N/A")
        pdf.sensitivity = data.get("Sensitivity", "N/A")
        pdf.report_number = data["Report Number"]
        pdf.report_date = data.get("Report Date", datetime.datetime.now().strftime("%Y-%m-%d"))
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, data["Report Title"], ln=1, align="L")
        pdf.ln(5)
        executive_summary = data.get("Executive Summary", "").strip()
        if executive_summary:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 10, "Executive Summary", ln=1, border=0)
            pdf.set_font("Helvetica", "", 11)
            pdf.multi_cell(0, 8, executive_summary)
            pdf.ln(5)
        key_points = data.get("Key Points", "").strip()
        if key_points:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 10, "Key Points", ln=1, border=0)
            pdf.set_font("Helvetica", "", 11)
            pdf.multi_cell(0, 8, key_points)
            pdf.ln(5)
        assessment = data.get("Assessment", "").strip()
        if assessment:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 10, "Assessment", ln=1, border=0)
            pdf.set_font("Helvetica", "", 11)
            pdf.multi_cell(0, 8, assessment)
            pdf.ln(10)
        return pdf

    @staticmethod
    def generate_pdf(data, parent):
        try:
            if not data.get("Report Title") or not data.get("Report Number"):
                raise ValueError("Report Title and Report Number are required fields.")
            pdf = PDFreport_generator._build_pdf(data)
            filename = filedialog.asksaveasfilename(parent=parent, defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")], title="Save Report As")
            if filename:
                pdf.output(filename)
                messagebox.showinfo("Success", f"Report saved as {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {e}")

    @staticmethod
    def preview_pdf(data):
        try:
            if not data.get("Report Title") or not data.get("Report Number"):
                raise ValueError("Report Title and Report Number are required fields.")
            pdf = PDFreport_generator._build_pdf(data)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
                pdf.output(tmp_file.name)
                webbrowser.open(tmp_file.name)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to preview report: {e}")
