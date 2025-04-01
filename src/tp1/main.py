from src.tp1.utils.config import logger
from src.tp1.utils.lib import Capture, Report

if __name__ == "__main__":
    logger.info("Starting TP1")
    capture = Capture()
    capture.capture_trafic()
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "report.pdf"

    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")

    report.save(filename)
