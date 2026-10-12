package web

import "embed"

// Assets embeds all web frontend assets (HTML, CSS, JS)
//
//go:embed index.html css/* js/*
var Assets embed.FS
