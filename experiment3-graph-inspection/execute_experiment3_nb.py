import nbformat as nbf
from nbclient import NotebookClient
from pathlib import Path

nb_path = Path(__file__).parent / "experiment3_graph_inspection.ipynb"
nb = nbf.read(str(nb_path), as_version=4)
client = NotebookClient(nb, timeout=600, kernel_name="pfr2026-venv")
client.execute(cwd=str(nb_path.parent))
nbf.write(nb, str(nb_path))
print(f"Executed & saved: {nb_path}")
