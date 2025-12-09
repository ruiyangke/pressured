// Go app with pprof endpoints for heap/goroutine dump testing
//
// Uses Fiber framework with pprof middleware.
// Endpoints:
//   - /debug/pprof/*      - pprof profiles (heap, goroutine, profile, etc.)
//   - /allocate?mb=100    - allocate MB of memory
//   - /spawn?n=10         - spawn N goroutines that block
//   - /clear              - clear allocated memory and goroutines
//   - /status             - show current memory and goroutine stats
//   - /health             - health check
//
// Build: go build -o app .
// Run: ./app --port 8080 --leak

package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/pprof"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

var (
	port       = flag.Int("port", 8080, "HTTP port")
	leakMemory = flag.Bool("leak", true, "Continuously leak memory")
	leakMB     = flag.Int("leak-mb", 1, "MB to leak per interval")
	leakSec    = flag.Int("leak-interval", 1, "Seconds between leaks")
)

// State holds allocated memory and spawned goroutines
type State struct {
	mu         sync.RWMutex
	chunks     [][]byte
	totalBytes int64
	goroutines []chan struct{} // channels to signal goroutine shutdown
}

var state = &State{}

func main() {
	flag.Parse()

	app := fiber.New(fiber.Config{
		AppName:      "go-pprof-app",
		ServerHeader: "go-pprof-app",
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} ${method} ${path} ${latency}\n",
	}))

	// pprof middleware - exposes /debug/pprof/*
	app.Use(pprof.New())

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		state.mu.RLock()
		totalMB := state.totalBytes / (1024 * 1024)
		goroutines := len(state.goroutines)
		state.mu.RUnlock()

		return c.SendString(fmt.Sprintf("ok - %d MB allocated, %d blocked goroutines, %d total goroutines\n",
			totalMB, goroutines, runtime.NumGoroutine()))
	})

	// Status endpoint - JSON response
	app.Get("/status", func(c *fiber.Ctx) error {
		state.mu.RLock()
		defer state.mu.RUnlock()

		return c.JSON(fiber.Map{
			"allocated_mb":       state.totalBytes / (1024 * 1024),
			"allocated_bytes":    state.totalBytes,
			"chunks":             len(state.chunks),
			"blocked_goroutines": len(state.goroutines),
			"total_goroutines":   runtime.NumGoroutine(),
			"num_cpu":            runtime.NumCPU(),
			"go_version":         runtime.Version(),
		})
	})

	// Allocate memory
	app.Get("/allocate", func(c *fiber.Ctx) error {
		mb := c.QueryInt("mb", 100)
		if mb <= 0 || mb > 1024 {
			return c.Status(400).SendString("mb must be between 1 and 1024")
		}

		size := mb * 1024 * 1024
		chunk := make([]byte, size)

		// Touch all pages to ensure actual allocation
		for i := 0; i < len(chunk); i += 4096 {
			chunk[i] = byte(i % 256)
		}

		state.mu.Lock()
		state.chunks = append(state.chunks, chunk)
		state.totalBytes += int64(size)
		totalMB := state.totalBytes / (1024 * 1024)
		state.mu.Unlock()

		log.Printf("Allocated %d MB, total: %d MB", mb, totalMB)

		return c.JSON(fiber.Map{
			"allocated_mb": mb,
			"total_mb":     totalMB,
		})
	})

	// Spawn blocked goroutines (useful for goroutine profile testing)
	app.Get("/spawn", func(c *fiber.Ctx) error {
		n := c.QueryInt("n", 10)
		if n <= 0 || n > 1000 {
			return c.Status(400).SendString("n must be between 1 and 1000")
		}

		state.mu.Lock()
		for i := 0; i < n; i++ {
			ch := make(chan struct{})
			state.goroutines = append(state.goroutines, ch)

			go func(id int, done chan struct{}) {
				// Simulate a blocked goroutine waiting on channel
				<-done
			}(len(state.goroutines), ch)
		}
		total := len(state.goroutines)
		state.mu.Unlock()

		log.Printf("Spawned %d blocked goroutines, total: %d", n, total)

		return c.JSON(fiber.Map{
			"spawned":            n,
			"blocked_goroutines": total,
			"total_goroutines":   runtime.NumGoroutine(),
		})
	})

	// Clear all state
	app.Get("/clear", func(c *fiber.Ctx) error {
		state.mu.Lock()

		// Signal all goroutines to exit
		for _, ch := range state.goroutines {
			close(ch)
		}
		state.goroutines = nil

		// Clear memory
		state.chunks = nil
		state.totalBytes = 0

		state.mu.Unlock()

		// Force GC
		runtime.GC()

		log.Println("Cleared all memory and goroutines")

		return c.JSON(fiber.Map{
			"message":          "cleared",
			"total_goroutines": runtime.NumGoroutine(),
		})
	})

	// Continuous memory leak mode
	if *leakMemory {
		go func() {
			ticker := time.NewTicker(time.Duration(*leakSec) * time.Second)
			defer ticker.Stop()

			for range ticker.C {
				size := *leakMB * 1024 * 1024
				chunk := make([]byte, size)
				for i := 0; i < len(chunk); i += 4096 {
					chunk[i] = byte(i % 256)
				}

				state.mu.Lock()
				state.chunks = append(state.chunks, chunk)
				state.totalBytes += int64(size)
				totalMB := state.totalBytes / (1024 * 1024)
				state.mu.Unlock()

				log.Printf("Leaked %d MB, total: %d MB", *leakMB, totalMB)
			}
		}()
		log.Printf("Memory leak mode enabled: %d MB every %d seconds", *leakMB, *leakSec)
	}

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting go-pprof-app on %s", addr)
	log.Printf("pprof endpoints: http://localhost%s/debug/pprof/", addr)
	log.Printf("  - heap:      /debug/pprof/heap")
	log.Printf("  - goroutine: /debug/pprof/goroutine")
	log.Printf("  - profile:   /debug/pprof/profile?seconds=30")
	log.Printf("  - trace:     /debug/pprof/trace?seconds=5")

	if err := app.Listen(addr); err != nil {
		log.Fatal(err)
	}
}
