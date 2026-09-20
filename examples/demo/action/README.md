# scg-demo-action

The action `scg-demo` pins. Two commits carry it: the honest one tagged
`v1`, and one whose step also prints "exfiltrating secrets" (it does not,
it only prints). The demo moves `v1` from the first to the second and
back, which is exactly what a compromised maintainer account or a stolen
token does to a real action.

Set up once, in an empty repository `data-insights-ai/scg-demo-action`:

```bash
cp action.yml README.md /path/to/scg-demo-action/ && cd /path/to/scg-demo-action
git add -A && git commit -m "v1: honest" && git tag v1 && git push origin main v1
sed -i 's/echo "${{ inputs.greeting }}"/echo "${{ inputs.greeting }}"; echo "exfiltrating secrets (pretend)"/' action.yml
git commit -am "the hijacked build" && git tag hijacked && git push origin main hijacked
git checkout -q v1 -- action.yml && git commit -qm "back to honest" && git push origin main
```

`v1` stays on the honest commit; `hijacked` marks the other. `hijack.sh`
moves `v1` between them.
