"""LogLens API: upload -> job id -> poll -> report -> export."""
import csv, io, os, tempfile, uuid
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, request, Response
from flask_cors import CORS

from detector import analyze
from generate_demo import generate

BASE = os.path.dirname(os.path.abspath(__file__))
SIGS = os.path.join(BASE, "signatures.json")
DEMO = os.path.join(BASE, "demo.log")
UPLOADS = tempfile.mkdtemp(prefix="loglens_")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024**3  # 2 GB cap
CORS(app)
pool = ThreadPoolExecutor(max_workers=2)  # swap for Celery/RQ + Redis in production
jobs = {}  # job_id -> {status, progress, report, error}


def run_job(job_id, path, delete=True):
    job = jobs[job_id]
    job["status"] = "processing"
    try:
        job["report"] = analyze(path, SIGS, progress=lambda n: job.update(progress=n))
        job["status"] = "done"
    except Exception as exc:  # surface failures to the poller
        job["status"], job["error"] = "failed", str(exc)
    finally:
        if delete and os.path.exists(path):
            os.remove(path)


def submit(path, delete=True):
    job_id = uuid.uuid4().hex[:12]
    jobs[job_id] = {"status": "queued", "progress": 0, "report": None, "error": None}
    pool.submit(run_job, job_id, path, delete)
    return job_id


@app.post("/api/upload")
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="Choose a .log file to upload."), 400
    path = os.path.join(UPLOADS, uuid.uuid4().hex + ".log")
    f.save(path)  # werkzeug streams multipart to disk in chunks, never fully in RAM
    return jsonify(job_id=submit(path)), 202


@app.post("/api/demo")
def demo():
    if not os.path.exists(DEMO):
        generate(DEMO)
    return jsonify(job_id=submit(DEMO, delete=False)), 202


@app.get("/api/jobs/<job_id>")
def status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify(error="Unknown job ID."), 404
    return jsonify(status=job["status"], progress=job["progress"], error=job["error"])


@app.get("/api/jobs/<job_id>/report")
def report(job_id):
    job = jobs.get(job_id)
    if not job or job["status"] != "done":
        return jsonify(error="Report not ready."), 409
    return jsonify(job["report"])


@app.get("/api/jobs/<job_id>/export")
def export(job_id):
    job = jobs.get(job_id)
    if not job or job["status"] != "done":
        return jsonify(error="Report not ready."), 409
    if request.args.get("format") == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["ip", "country", "attacks", "severity", "types"])
        for a in job["report"]["top_attackers"]:
            w.writerow([a["ip"], a["country"], a["attacks"], a["severity"], ";".join(a["types"])])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=loglens-{job_id}.csv"})
    return Response(jsonify(job["report"]).get_data(), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=loglens-{job_id}.json"})


if __name__ == "__main__":
    app.run(port=5000, debug=True)
