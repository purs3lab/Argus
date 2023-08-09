#!/bin/bash

poetry run python3 argus.py --mode action --url https://github.com/TDesignOteam/create-report  --commit dfc9b5437db0ac494e652a80a77f58e50c3275dd
poetry run python3 argus.py --mode action --url https://github.com/embano1/wip  --commit 92dce917deebbe95dcdfd0746e1f2285e2974096
poetry run python3 argus.py --mode action --url https://github.com/Reedyuk/write-properties  --commit e09fdd3c4640ecfb1071cb856c0e74049b05af47


poetry run python3 argus.py --mode repo --url https://github.com/DynamoDS/Dynamo  --commit eaeabeb053372ff62fa5518c064908a1c8a6afe5 --workflow-path .github/workflows/issue_type_predicter.yaml 
poetry run python3 argus.py --mode repo --url https://github.com/argusSecurityBot/govmomi  --commit c86d17ea97f706876618b76c196a0402349f522d --workflow-path .github/workflows/govmomi-check-wip.yaml  
poetry run python3 argus.py --mode repo --url https://github.com/Tencent/tdesign-vue  --commit 93ab803d61dc29b6dca63a9c7b4cc1bd8122454e --workflow-path .github/workflows/issue-synchronize.temp.yml
poetry run python3 argus.py --mode repo --url https://github.com/yagipy/habit-manager  --commit d2ced458d934377fda56dd23ee541d249a47b638 --workflow-path .github/workflows/close.yml
poetry run python3 argus.py --mode repo --url https://github.com/GitLiveApp/kotlin-diff-utils  --commit 436ac1d26bfd14de01956051a72c7efb4b31ba5b --workflow-path .github/workflows/pull_request.yml