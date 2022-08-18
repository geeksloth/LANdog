# LANdog
A local area network dog, devices monitoring and notification for important events:
  - new device connected
  - watch-list devices just connect or disconnect

## Installation
1. Clone this repository, change directory to the script folder, and prepare some important configurations.
```github
git clone https://github.com/geeksloth/landog.git
```
```bash
cd landog && cp config-dist.json config.json && cp db-dist.json db.json
```
2. Modify the some configurations such as network, interval, and watchlist as your desire.
```bash
nano config.json
```
Remove the db.json contents or left only blank array inside: `[]` 
```bash
echo "[]" > db.json
```
3. Run the script inside the Docker container
```bash
docker compose up -d
```
