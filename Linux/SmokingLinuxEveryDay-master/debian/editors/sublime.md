## Installation

* [Download](https://www.sublimetext.com/3)

```bash
dpkg -i sublime-text_build-xxxx_amd64.deb
```

### Dracula Theme

* [sublime dracula](https://draculatheme.com/sublime/)

* Preferences -> Color Scheme -> Dracula Color Scheme -> Dracula

### CamingoCode Font

* [camingocode font](https://www.fontsquirrel.com/fonts/camingocode)

```bash
cp -r /home/<username>/Downloads/camingocode /usr/local/share/
fc-cache -fv
```

* Restart sublime if it is already open.

* Preferences -> Settings -> 
```json
{
	"color_scheme": "Packages/Dracula Color Scheme/Dracula.tmTheme",
	"font_size": 11,
	"font_face": "CamingoCode"
}
```

### Package Control

* [package control](https://packagecontrol.io/installation#st3)

* Preferences -> Package Control

### Disable 'Remember Open Files'

* Preferences -> Settings -> 
```json
"remember_open_files": false,
"hot_exit": false,
```
