import os

os.system("ant");
os.system(
    "./goto-analyzer "
    "./Main.class "
    "--taint taint.json "
    "--summary-only "
    "--taint-dump-html-traces "
    "--taint-dump-html-summaries "
    "--taint-dump-lvsa-summaries "
    "--taint-dump-program "
    "--taint-dump-html-statistics "
    "--taint-summaries-timeout-seconds 60 "
    "--verbosity 9"
    )

