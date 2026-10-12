package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/routerpilot/routerpilot/internal/api"
)

//go:embed all:../../web
var webFS embed.FS

func main() {
	port := flag.Int("port", 8080, "Web Control Plane port")
	headless := flag.Bool("headless", false, "Do not auto-open browser")
	flag.Parse()

	server := api.NewServer()
	mux := http.NewServeMux()

	// Register API Handlers
	server.RegisterRoutes(mux)

	// Embedded Static Web Assets
	subFS, err := fs.Sub(webFS, "web")
	if err != nil {
		// Fallback to local disk directory if not embedded
		mux.Handle("/", http.FileServer(http.Dir("./web")))
	} else {
		mux.Handle("/", http.FileServer(http.FS(subFS)))
	}

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	url := fmt.Sprintf("http://%s", addr)

	fmt.Println("================================================================")
	fmt.Println("🚀 RouterPilot Control Plane v1.0 [Windows Portable]")
	fmt.Println("   معماری ایمن، هوشمند و تراکنشی مدیریت روترهای میکروتیک")
	fmt.Printf("   داشبورد وب در دسترس است: %s\n", url)
	fmt.Println("================================================================")

	if !*headless {
		go func() {
			time.Sleep(500 * time.Millisecond)
			openBrowser(url)
		}()
	}

	log.Fatal(http.ListenAndServe(addr, mux))
}

func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	}
	if err != nil {
		log.Printf("Cannot auto-launch browser: %v", err)
	}
}
