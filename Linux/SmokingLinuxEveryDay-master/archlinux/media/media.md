### pulseaudio needs to be installed to have mic for skype

### record voice from command line to mp3 with 320 bitrate
```bash
ffmpeg -f alsa -ac 2 -i pulse -acodec libmp3lame -ab 320k -y testing.mp3
```

### Convert
```bash
ffmpeg -f alsa -i hw:0 -acodec libmp3lame -ab 192k -ac 1 -ar 44100 -vn meeting.mp3
```

### speak on mic and listen on ssh server
```bash
arecord -f dat | ssh -C user@host aplay -f dat
```

### take snapshot from camera and use 's' to store it
```bash
mplayer tv:// -vf screenshot
```

### list available formats to dl with their code
```bash
youtube-dl -F YOUTUBEURL
```

```bash
youtube-dl -f code YOUTUBEURL
```

*e.g. "-f 141" for m4a sound-only*

### to convert all m4as to mp3 192k
```bash
for i in *.m4a;do ffmpeg -i "$i" -acodec mp3 -ac 2 -ab 192k "${i%.m4a}.mp3"; done
```

### External screen (projector) with xrandr
```bash
xrandr --output DP1 --mode 832x624 --rate 75 --right-of LVDS1
```


