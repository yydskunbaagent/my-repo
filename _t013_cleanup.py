import shutil, os
for d in ["_t013", "_a1", "_a2", "_a3", "_a4"]:
    p = os.path.join(os.environ["WT_ROOT"], ".pytest_tmp_" + d[1:] if d != "_t013" else os.environ["WT_ROOT"] + "\\.pytest_tmp_t013")
    shutil.rmtree(p, ignore_errors=True)
print("cleaned")
