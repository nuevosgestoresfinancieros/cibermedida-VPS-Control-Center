# Politicas

## Proposito

Las politicas definen que puede observarse, proponerse, ejecutarse automaticamente o requerir autorizacion. Deben transformarse progresivamente en reglas verificables.

## Reglas base

```text
IF environment == production
AND action == deploy
THEN approval_required = true
```

```text
IF tests != passed
THEN deploy = blocked
```

```text
IF backup != verified
THEN deploy = blocked
```

```text
IF action == delete_database
THEN automatic_execution = false
```

## Autonomia graduada

- Nivel 0: observacion.
- Nivel 1: diagnostico.
- Nivel 2: propuesta de acciones.
- Nivel 3: acciones automaticas de bajo riesgo.
- Nivel 4: despliegues con autorizacion.
- Nivel 5: recuperacion automatica limitada.

## Autonomia por accion

```text
health_check       AUTO
logs               AUTO
testing            AUTO
backup             AUTO
code_changes       CONTROLLED
deploy             APPROVAL
database_change    APPROVAL
security_change    APPROVAL
delete_data        NEVER_AUTO
```

## Protocolos

### Diagnostico

```text
observar
recopilar informacion
correlacionar
identificar hipotesis
validar hipotesis
proponer solucion
```

### Desarrollo

```text
git status
identificar main
crear agent/*
analizar
modificar
tests
lint
build
diff
informe
```

### Produccion

```text
Change Request
Impact Analysis
Risk Assessment
Tests
Build
Backup
Backup Verify
Authorization
Deploy
Validator
Health Check
Logs
Monitoring
Close Change
```

### Fallo

```text
FAILURE
STOP
COLLECT EVIDENCE
DETERMINE IMPACT
ROLLBACK ANALYSIS
AUTHORIZATION
ROLLBACK
VALIDATION
```
