// Package risk calcula que tan urgente es migrar cada uso de criptografia.
//
// Usa la desigualdad de Mosca: si X (cuantos años deben seguir protegidos los datos) mas Y (cuanto tarda
// la organizacion en migrar) supera Z (cuantos años faltan para que el algoritmo deje de ser aceptable),
// la migracion ya esta atrasada. Z sale de las fechas de NIST IR 8547. El puntaje es una suma simple y
// explicada, no una caja negra: cada ajuste agrega su motivo.
package risk

import (
	"fmt"
	"time"

	"github.com/ulisespignatelli/cryptoinv/backend/internal/catalog"
	"github.com/ulisespignatelli/cryptoinv/backend/internal/domain"
)

// Policy son los supuestos de la organizacion. Se pueden cambiar por activo.
type Policy struct {
	ShelfLifeYears int // X: cuantos años deben seguir siendo secretos o validos los datos
	MigrationYears int // Y: cuanto tarda la organizacion en migrar un sistema
	Now            func() time.Time
}

// DefaultPolicy refleja una organizacion tipica: datos que importan 10 años y migraciones de 3.
func DefaultPolicy() Policy {
	return Policy{ShelfLifeYears: 10, MigrationYears: 3, Now: time.Now}
}

// Assess evalua un uso con la informacion del catalogo.
func Assess(u domain.Usage, alg catalog.Algorithm, p Policy) domain.Assessment {
	now := p.Now()
	year := now.Year()
	a := domain.Assessment{QuantumStatus: alg.Quantum, DeprecatedFrom: alg.Deprecated, DisallowedFrom: alg.Disallowed,
		Replacement: alg.Replacement}
	score := 0
	add := func(n int, why string, args ...any) {
		score += n
		a.Reasons = append(a.Reasons, fmt.Sprintf(why, args...))
	}

	switch alg.Quantum {
	case domain.ClassicallyBroken:
		add(80, "%s ya es inseguro hoy, sin necesidad de una computadora cuántica", alg.Name)
		if alg.Disallowed != 0 && year > alg.Disallowed {
			add(10, "NIST lo prohíbe después de %d", alg.Disallowed)
		}
	case domain.QuantumVulnerable:
		add(45, "%s es vulnerable a una computadora cuántica (algoritmo de Shor)", alg.Name)
		if alg.Disallowed != 0 && year > alg.Disallowed {
			add(40, "NIST ya no lo permite: prohibido después de %d", alg.Disallowed)
		} else if alg.Disallowed != 0 {
			z := alg.Disallowed - year
			x, y := p.ShelfLifeYears, p.MigrationYears
			if alg.Primitive == domain.PrimSignature {
				// Una firma solo tiene que resistir mientras se verifica: lo que cuenta es el tiempo de migracion.
				if y > z {
					add(20, "la migración (%d años) termina después de %d, cuando NIST ya no lo permite", y, alg.Disallowed)
				}
			} else if x+y > z {
				add(20, "datos que deben protegerse %d años + %d de migración superan los %d que faltan para %d (desigualdad de Mosca)",
					x, y, z, alg.Disallowed)
			}
			if alg.Deprecated != 0 && alg.Deprecated-year <= p.MigrationYears {
				add(5, "queda desaprobado después de %d: dentro del tiempo de migración", alg.Deprecated)
			}
		}
		switch alg.Primitive {
		case domain.PrimKeyAgree, domain.PrimPKE, domain.PrimKEM:
			add(15, "protege la confidencialidad: lo cifrado hoy puede grabarse y descifrarse mañana")
		case domain.PrimSignature:
			add(5, "firma: el riesgo empieza cuando exista la computadora cuántica, pero el recambio de PKI lleva años")
		}
	case domain.QuantumWeakened:
		add(10, "%s sigue siendo aceptable; la computación cuántica solo reduce su margen", alg.Name)
	case domain.QuantumResistant:
		a.Reasons = append(a.Reasons, alg.Name+" ya es resistente a la computación cuántica")
	default:
		add(30, "algoritmo sin clasificar: revisar a mano")
	}

	if alg.MinKeyBits != 0 && u.KeyBits != 0 && u.KeyBits < alg.MinKeyBits {
		add(35, "clave de %d bits: por debajo del mínimo aceptable hoy (%d)", u.KeyBits, alg.MinKeyBits)
	}
	if u.InTests && score > 0 {
		add(-25, "aparece en código de prueba o ejemplos: no debería llegar a producción (confirmar)")
	}
	if u.Confidence == "baja" {
		add(-10, "detección de confianza baja: confirmar a mano")
	}
	a.Score = max(0, min(100, score))
	a.Severity = severity(a.Score)
	return a
}

func severity(score int) domain.Severity {
	switch {
	case score >= 85:
		return domain.SevCritical
	case score >= 65:
		return domain.SevHigh
	case score >= 40:
		return domain.SevMedium
	case score >= 15:
		return domain.SevLow
	default:
		return domain.SevInfo
	}
}
