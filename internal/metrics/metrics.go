package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	CertsIssued = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certs_issued_total",
		Help: "Total number of certificates issued",
	})
	CertsRenewed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "certs_renewed_total",
		Help: "Total number of certificates renewed",
	})
	ApiErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "api_errors_total",
		Help: "Total number of API errors",
	})
)

func Init() {
	prometheus.MustRegister(CertsIssued)
	prometheus.MustRegister(CertsRenewed)
	prometheus.MustRegister(ApiErrors)
}
