# Solo45

A small solo-mining pool and live mining dashboard for your own Bitcoin node, packaged as an [Umbrel](https://umbrel.com) community app.

- **Pool** (`src/pool.py`): Stratum v1, standard library only. Builds work from `getblocktemplate` and checks every new job with the node's block proposal mode, so a malformed block shows up within seconds.
- **Dashboard** (`src/server.py`, `src/index.html`): hashrate, temperatures, best shares, block switch times and odds for Bitaxe (AxeOS) and Braiins OS miners. It can change Solo45's per-miner share difficulty; nothing else.
- **AI assistant** (`src/ai.py`, optional): explains what the dashboard sees. Off unless you add your own Anthropic API key.

## Install on Umbrel

1. In umbrelOS, open the App Store, choose **Community App Stores**, and add `https://github.com/race45race/solo45`.
2. Install **Solo45** (it needs the Bitcoin app).
3. Open Solo45 (port 4545) and enter your payout address.
4. Point your miners at `stratum+tcp://<your-umbrel-ip>:3333`. The username can be `<address>.<worker name>` or just a worker name.

## Settings

Everything normal is set on the dashboard: payout address, share difficulty per miner, job update interval, template policy, electricity price, and the AI assistant (your own Anthropic API key, model and spending limits). Advanced options live in `data/pool/config.json` and `data/dash/config.json` (for example `miners`, a list of miner IPs, and `ai.notes`, facts about your setup for the assistant).

## Run without Docker

Both programs also run directly with Python 3 on the machine that runs the node: `python3 src/pool.py` and `python3 src/server.py`. `python3 src/selftest.py` runs the pool's checks against the live node.

## License

MIT, see [LICENSE](LICENSE).
