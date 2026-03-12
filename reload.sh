#!/bin/bash

kill -HUP $(pgrep netflow-collector)
echo "Done!"
