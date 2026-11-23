package risk

import (
	"testing"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/catalog"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

func policyAt(year, shelf, migration int) Policy {
	return Policy{ShelfLifeYears: shelf, MigrationYears: migration,
		Now: func() time.Time { return time.Date(year, 6, 1, 0, 0, 0, 0, time.UTC) }}
}

func assess(t *testing.T, id string, bits int, p Policy) domain.Assessment {
	t.Helper()
	alg, ok := catalog.MustLoad().Get(id)
	if !ok {
		t.Fatalf("no existe %s", id)
	}
	return Assess(domain.Usage{AlgorithmID: id, KeyBits: bits, Confidence: "alta"}, alg, p)
}

func TestOrdering(t *testing.T) {
	p := policyAt(2026, 10, 3)
	md5, ecdh, rsaSig, aes, mlkem := assess(t, "md5", 0, p), assess(t, "ecdh", 0, p), assess(t, "rsa", 2048, p),
		assess(t, "aes", 256, p), assess(t, "mlkem", 0, p)
	if !(md5.Score >= ecdh.Score && ecdh.Score > rsaSig.Score-1 && rsaSig.Score > aes.Score && aes.Score > mlkem.Score) {
		t.Fatalf("orden inesperado: md5=%d ecdh=%d rsa=%d aes=%d mlkem=%d", md5.Score, ecdh.Score, rsaSig.Score, aes.Score, mlkem.Score)
	}
	if mlkem.Severity != domain.SevInfo || md5.Severity.Rank() < domain.SevHigh.Rank() {
		t.Fatalf("severidades: mlkem=%s md5=%s", mlkem.Severity, md5.Severity)
	}
}

func TestMoscaInequality(t *testing.T) {
	short := assess(t, "ecdh", 0, policyAt(2026, 1, 1)) // 1 + 1 < 9 años hasta 2035
	long := assess(t, "ecdh", 0, policyAt(2026, 10, 3)) // 10 + 3 > 9
	if long.Score <= short.Score {
		t.Fatalf("datos de vida larga deberían ser más urgentes: %d vs %d", long.Score, short.Score)
	}
	// En firmas no importa cuánto duran los datos sino cuánto tarda la migración.
	sigLongData := assess(t, "ecdsa", 0, policyAt(2026, 30, 3))
	sigSlowMigration := assess(t, "ecdsa", 0, policyAt(2026, 1, 10))
	if sigSlowMigration.Score <= sigLongData.Score {
		t.Fatalf("firma: una migración lenta debería pesar más: %d vs %d", sigSlowMigration.Score, sigLongData.Score)
	}
}

func TestWeakKeyAndPastDeadline(t *testing.T) {
	weak := assess(t, "rsa", 1024, policyAt(2026, 10, 3))
	if weak.Severity.Rank() < domain.SevHigh.Rank() {
		t.Fatalf("RSA-1024 debería ser al menos alta: %+v", weak)
	}
	after := assess(t, "rsa", 3072, policyAt(2036, 10, 3))
	if after.Severity != domain.SevCritical {
		t.Fatalf("después de 2035 RSA debería ser crítica: %+v", after)
	}
	if len(after.Reasons) < 2 {
		t.Fatal("cada puntaje debe explicarse")
	}
}
