// Command trainml fits pkg/mlmodel's logistic regression weights.
//
// There's no large corpus of labeled real-world fingerprints available to
// this project, so this generates a synthetic dataset instead: for each of
// the two classes (genuine desktop browser, automated/headless browser) it
// samples each feature from a distribution reflecting the same domain
// knowledge pkg/analyzer/baseline.go encodes as fixed rules (e.g. headless
// Chrome usually reports a software WebGL renderer; a real desktop rarely
// does), with label noise and feature overlap so the classes aren't
// trivially separable. Batch gradient descent with L2 regularization then
// fits weights against that dataset.
//
// Run with `go run ./tools/trainml` and paste the printed Weights/Bias into
// pkg/mlmodel/model.go to regenerate them.
package main

import (
	"fmt"
	"math"
	"math/rand"

	"github.com/Aymaancoderji/StealthAudit/pkg/mlmodel"
)

const (
	samplesPerClass = 4000
	epochs          = 3000
	learningRate    = 0.15
	l2Lambda        = 0.002
)

// sample generates one feature vector (in mlmodel.FeatureNames order) for
// the given class, plus its label (1 = automated, 0 = genuine).
func sample(rng *rand.Rand, automated bool) ([]float64, float64) {
	f := make([]float64, len(mlmodel.FeatureNames))
	label := 0.0
	if automated {
		label = 1.0
	}

	bernoulli := func(pAutomated, pGenuine float64) float64 {
		p := pGenuine
		if automated {
			p = pAutomated
		}
		if rng.Float64() < p {
			return 1
		}
		return 0
	}

	// index: feature, (P if automated, P if genuine)
	f[0] = bernoulli(0.85, 0.01) // webdriver_flag
	f[1] = bernoulli(0.10, 0.01) // function_tostring_tampered
	f[2] = bernoulli(0.35, 0.03) // permissions_api_anomaly
	f[3] = bernoulli(0.30, 0.05) // missing_chrome_runtime
	f[4] = bernoulli(0.05, 0.01) // worker_unsupported
	f[5] = bernoulli(0.75, 0.03) // software_gpu_renderer
	f[6] = bernoulli(0.15, 0.02) // canvas_fingerprint_blocked
	f[7] = bernoulli(0.15, 0.02) // audio_fingerprint_blocked

	// hardware_concurrency_norm: automated/CI boxes skew low core counts.
	cores := 8.0 + rng.NormFloat64()*2.5
	if automated {
		cores = 3.0 + rng.NormFloat64()*1.8
	}
	if cores < 1 {
		cores = 1
	}
	f[8] = clip01(cores / 16.0)

	// font_count_norm: minimal containers/headless images have far fewer fonts.
	fonts := 16.0 + rng.NormFloat64()*4
	if automated {
		fonts = 4.0 + rng.NormFloat64()*3
	}
	if fonts < 0 {
		fonts = 0
	}
	f[9] = clip01(fonts / 30.0)

	f[10] = bernoulli(0.30, 0.04) // device_memory_missing
	f[11] = bernoulli(0.25, 0.03) // tls_ja3_missing
	f[12] = bernoulli(0.20, 0.03) // http2_not_negotiated
	f[13] = bernoulli(0.20, 0.005) // automation_artifacts_detected

	return f, label
}

func clip01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func sigmoid(x float64) float64 { return 1 / (1 + math.Exp(-x)) }

func main() {
	rng := rand.New(rand.NewSource(42))

	var X [][]float64
	var y []float64
	for i := 0; i < samplesPerClass; i++ {
		fx, fy := sample(rng, false)
		X = append(X, fx)
		y = append(y, fy)
		ax, ay := sample(rng, true)
		X = append(X, ax)
		y = append(y, ay)
	}

	d := len(mlmodel.FeatureNames)
	w := make([]float64, d)
	b := 0.0
	n := float64(len(X))

	for epoch := 0; epoch < epochs; epoch++ {
		gradW := make([]float64, d)
		gradB := 0.0
		for i, x := range X {
			pred := sigmoid(dot(w, x) + b)
			err := pred - y[i]
			for j, xj := range x {
				gradW[j] += err * xj
			}
			gradB += err
		}
		for j := range w {
			w[j] -= learningRate * (gradW[j]/n + l2Lambda*w[j])
		}
		b -= learningRate * (gradB / n)
	}

	// Report training accuracy as a sanity check, not a real held-out metric.
	correct := 0
	for i, x := range X {
		pred := sigmoid(dot(w, x) + b)
		predicted := 0.0
		if pred >= 0.5 {
			predicted = 1
		}
		if predicted == y[i] {
			correct++
		}
	}
	fmt.Printf("// training accuracy on synthetic set: %.1f%% (%d samples)\n", 100*float64(correct)/n, len(X))

	fmt.Println("var Weights = []float64{")
	for i, name := range mlmodel.FeatureNames {
		fmt.Printf("\t%.4f, // %s\n", w[i], name)
	}
	fmt.Println("}")
	fmt.Printf("var Bias = %.4f\n", b)
}

func dot(a, b []float64) float64 {
	s := 0.0
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}
