# IdentityGuard

Програмна платформа до магістерської кваліфікаційної роботи «Розроблення моделі оцінювання ризику компрометації хмарних ідентичностей на основі подій AWS CloudTrail» (Національний університет «Львівська політехніка», кафедра захисту інформації, 2026). Ядро моделі оцінювання ризику розміщено в `backend/app/engine/` (`model.py`, `scoring.py`). Репозиторій містить лише синтетичні дані та не містить облікових даних.

Локальна збірка для аналізу ризику ідентичностей AWS. [Статус виконання ТЗ](docs/STATUS.md) · [Рішення](docs/DECISIONS.md) · [Звіт синтетичного оцінювання](reports/evaluation.md)

## Демоконсоль

На Windows потрібні Python з `uv` і Node.js. Скрипт встановлює залежності з lock-файлів, збирає консоль і наповнює нову базу синтетичними даними.

```powershell
python -m pip install --user uv
.\scripts\start-demo.ps1
```

Відкрийте [консоль](http://127.0.0.1:8000). Для іншої бази передайте `-Database data/another-demo.sqlite`. Для іншого порту передайте `-Port 8013`.

Альтернативний локальний запуск через Docker Compose.

```sh
docker compose -f deploy/compose/compose.yaml up --build -d --wait
docker compose -f deploy/compose/compose.yaml exec -T console python -m app.devdata seed
```

`make up` та `make devdata` виконують ті самі команди. Compose запускає застосунок та зберігає демобазу в томі. Вікно оцінювання синтетичних даних прив'язано до дати генерації. Для нового періоду використайте окрему базу.

Щоб додати до цієї демобази вправу з розслідування IAM-інцидентів, запустіть:

```sh
docker compose -f deploy/compose/compose.yaml exec -T console python -m app.demo_incidents
```

У розділі **Кейси** відкрийте, наприклад, **Компрометація CI-раннера**. Для погоджених змін і хибних спрацювань виберіть **Закриті** або **Усі**. Хронологія показує успішні переходи ролей, а посилання з подій відкривають внески моделі в оцінку інциденту. Для нового набору зі свіжими датами додайте `--refresh` до команди. Параметр додає вправу з інтервалом щонайменше 24 години і зберігає попередні кейси. На сторінці **SLA та метрики** діють вибрані у верхній панелі акаунт і період.

## Багатокористувацький доступ

Локальний режим із користувачами вмикається через `IG_ACCESS_KEY`. Задайте випадковий 32-байтовий ключ у шістнадцятковому форматі через змінну середовища або захищений локальний `.env`. Запустіть Compose із цим ключем, наповніть демобазу та створіть адміністратора й аналітика інтерактивно.

```sh
docker compose -f deploy/compose/compose.yaml exec console python -m app.access_control /app/data/demo.sqlite admin@example.test admin
docker compose -f deploy/compose/compose.yaml exec console python -m app.access_control /app/data/demo.sqlite analyst@example.test analyst --account 111122223333
```

Команда запитує пароль і одноразово виводить URI для автентифікатора та десять резервних кодів. Перший вхід підтверджується кодом TOTP. Захищений cookie працює через HTTPS або довірений браузером `localhost`. Увійдіть як адміністратор і відкрийте **Доступ** для зміни ролей чи списку акаунтів. Зміна прав завершує активні сесії відповідного користувача.

Аналітик із закріпленими акаунтами бачить лише свої інциденти, ідентичності й події. Для цього режиму кейси показують окремі інциденти, а маршрути з глобальними агрегатами блокуються. Окремий приватний режим імпорту AWS використовує наявний токен.

## Розгортання консолі на Kubernetes

[Helm-чарт](deploy/helm/identityguard) розгортає один екземпляр консолі з SQLite на постійному томі. Для інсталяції потрібен готовий кластер, доступний образ за SHA-256 digest, StorageClass і Secret з ключем `access-key` для локального MFA. Для EKS зі стандартним EBS CSI створіть StorageClass із шифруванням EBS. [EKS StorageClass](https://docs.aws.amazon.com/eks/latest/userguide/create-storage-class.html)

```sh
helm upgrade --install identityguard deploy/helm/identityguard --namespace identityguard \
  --set image.repository="$IG_IMAGE_REPOSITORY" --set image.digest="$IG_IMAGE_DIGEST" \
  --set accessSecret=identityguard-access --wait
kubectl -n identityguard port-forward svc/identityguard-console 8012:8000
```

Відкрийте `http://localhost:8012`. Для TLS-проксі задайте `allowedHost` і дозвольте доступ від його подів через NetworkPolicy. Початкового користувача створіть командою `python -m app.access_control /app/data/demo.sqlite admin@example.test admin` всередині пода.

[Terraform для staging](deploy/terraform/staging/main.tf) описує приватний EKS Auto Mode, VPC у трьох зонах та ECR. Для планування потрібні погоджений AWS-акаунт, чинна роль адміністратора EKS і вже створений приватний S3-бакет для стану. Перед запуском задайте `TF_VAR_region`, `TF_VAR_account_id`, `TF_VAR_admin_role_arn` і `TF_VAR_kubernetes_version`.

```sh
terraform -chdir=deploy/terraform/staging init \
  -backend-config="bucket=$IG_STATE_BUCKET" \
  -backend-config="region=$TF_VAR_region" \
  -backend-config="key=identityguard/staging.tfstate"
terraform -chdir=deploy/terraform/staging plan
```

Для EKS Auto Mode використовуйте [StorageClass](deploy/helm/identityguard/eks-auto-storage.yaml) і значення `storage.storageClassName=identityguard-ebs`. Доступ до приватного Kubernetes API потребує підключення до VPC. [Документація EKS](https://docs.aws.amazon.com/eks/latest/userguide/create-storage-class.html)

## Відтворення оцінювання моделі

Числа магістерської роботи (таблиці 3.8-3.9, аналіз чутливості, незалежна перевірка) відтворюються з тегу `thesis-v1.0` за [інструкцією](docs/REPRODUCE.md): `make fetch-stratus`, `make thesis`, `make evaluate-independent`.

`make evaluate` запускає еталонні синтетичні сценарії. `make evaluate-extended` додає по одній ризиковій дії до S1, S3 і S5 та записує окремий звіт. `make evaluate-independent` запускає перевірку на зафіксованому публічному наборі Ariel Cyber. [Еталонний прогін](reports/evaluation.md) · [Розширений прогін](reports/evaluation-extended.md) · [Незалежний прогін](reports/independent.md)

Окремі команди відтворюють публічні журнали детонацій Stratus.

```sh
make fetch-stratus
make replay-stratus
make replay-stratus-extended
```

У PowerShell задайте `$env:PYTHONPATH = 'backend'` і запустіть відповідні модулі.

```powershell
python -m uv run --locked python -m app.devdata evaluate --end-day 2026-11-07 --extended
python -m uv run --locked python -m app.independent_evaluation
python -m uv run --locked python -m app.stratus fetch
python -m uv run --locked python -m app.stratus replay
python -m uv run --locked python -m app.stratus replay --rules config/detections/aws-sensitive-control-plane.yml --report reports/stratus-extended.md
```

[Базовий прогін](reports/stratus.md) і [прогін із додатковим правилом](reports/stratus-extended.md) записуються окремо. Команда повертає код 1, якщо критерій приймання не виконано, і зберігає звіт із фактичними оцінками. Розширений прогін застосовує [YAML-правило](config/detections/aws-sensitive-control-plane.yml) через наявний рушій детекцій. Це правило можна додати через розділ **Детекції**.

Якщо відомо, коли CloudTrail відновив збір після перерви, передайте ці моменти через `IG_CLOUDTRAIL_COVERAGE_BREAKS` як список ISO 8601 із часовими поясами, розділений комами. Наприклад, `2026-04-04T00:00:00Z`. Після зміни конфігурації перезапустіть сервіси й запустіть переоцінювання. У межах кожного фрагмента сигнал `dormant` використовує інтервали між подіями, а після розриву може спиратися на свіжий знімок IAM.

Для врахування публічних діапазонів AWS у сигналі `wexfil` задайте `IG_AWS_IP_RANGES` шляхом до [офіційного ip-ranges.json](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html) перед запуском області AWS. Збір додаткових фактів стану використовує доступні дозволи на `organizations:ListAccounts`, `ec2:DescribeInstances`, `iam:GenerateServiceLastAccessedDetails` та `iam:GetServiceLastAccessedDetails`. Якщо джерело недоступне, його дані не додають ризиковий факт.

## Профіль, AWS і ШІ в консолі

- **Профіль** відкривається кнопкою справа у верхній панелі. Тут зберігаються ім’я, пошта, посада, тема, мова, щільність і формат часу локальної робочої області.
- **Інтеграція AWS** є в лівому меню та на сторінці джерел. У приватній області виберіть AWS-профіль, введіть ID акаунта й регіон, перевірте підключення та запустіть імпорт.
- **ШІ-асистент** є в лівому меню й на сторінці кожного кейсу. Шаблонний аналіз доступний локально. Для генерації Anthropic задайте на сервері `ANTHROPIC_API_KEY` і `IG_AI_MODEL`, перезапустіть сервер та підтвердьте передачу знеособлених оцінок у формі кейсу.

## Реальні дані AWS

На цій машині імпортована база міститься в `%LOCALAPPDATA%\IdentityGuard\aws-history.sqlite`. Щоб відкрити її, запустіть команду і введіть окремий токен робочої області. Той самий токен потрібен у браузері. Приватна область відкривається на [сторінці інтеграції](http://127.0.0.1:8010/integrations/aws).

```powershell
.\scripts\start-aws-history.ps1
```

Для нового імпорту можна використати профіль IAM Identity Center. Увійдіть до профілю до запуску сервера або оновіть список профілів у формі після входу.

```powershell
aws configure sso --profile identityguard
aws sso login --profile identityguard
```

Також підтримуються тимчасові облікові дані процесу сервера. Окрема база створюється параметром `-Database` з абсолютним шляхом поза репозиторієм. Кожна приватна база прив’язується до одного акаунта.

### Імпорт із командного рядка

Задайте погоджений AWS-профіль або короткочасні облікові дані в середовищі виконання. Команди перевіряють акаунт через STS і потребують ідентичності IAM без кореневих облікових даних.

```powershell
$env:PYTHONPATH = 'backend'
$db = Join-Path $env:LOCALAPPDATA 'IdentityGuard/aws-history.sqlite'
python -m uv run --locked python -m app.aws_history --account <ACCOUNT_ID> --region eu-central-1 --days 21 --database $db
python -m uv run --locked python -m app.aws_inventory --account <ACCOUNT_ID> --region eu-central-1 --database $db
```

CloudTrail `LookupEvents` читає події керування в одному регіоні. IAM-імпорт збирає поточні дані користувачів, ролей, політик, MFA й віку активних ключів. Під час оцінювання використовується лише стан, відомий на момент вікна. Приватну SQLite-базу тримайте поза робочою папкою Git і синхронізованими каталогами.

## Розслідування та керування ризиком

- **Шляхи атак** показують досяжні критичні ресурси, найкоротші маршрути до чотирьох переходів і ключові ребра. Підведіть вказівник або переведіть клавіатурний фокус на крок пояснення, щоб підсвітити ребро. Без Anthropic доступне шаблонне пояснення. Для генерації застосовуються ті самі налаштування моделі й явна згода.
- **Хмарна конфігурація** показує результати перевірок, покриття і час останньої спостереженої події. У приватній області спершу перевірте підключення AWS, потім натисніть «Оновити з AWS». Граф враховує зібрані дозволи IAM, відносини довіри й політики зібраних ресурсів. Умови IAM, SCP та межі дозволів можуть змінювати фактичний доступ.
- **Ланцюжки ролей** показують успішні виклики STS із CloudTrail, міжаккаунтні переходи та ризикові джерела. Дані з цієї сторінки описують спостережені події.
- **Правила детекції** приймають YAML із вбудованими тестами. Бектест порівнює оцінки історичних вікон та не змінює інциденти. У деморежимі правила можна зберігати чернетками, вмикати й вимикати. Увімкнені правила змінюють відповідний індикатор.
- **Винятки** створюються для ідентичності з кейсу. Діє строк 1–90 діб. Застосування перераховує вікна та фіксує кількість приглушених подій.
- **Моделі ризику** показують редактор AHP, коефіцієнт узгодженості, ваги та конфліктні пари. У деморежимі зберігайте чернетки і запускайте тіньове порівняння. Активація моделі з підтвердженням другого адміністратора потребує RBAC.
- **Якість моделі** обчислюється за закритими інцидентами з вердиктами. **SLA та метрики** рахують реакцію, вирішення, p50/p90 і прострочені кейси.
- **Інтеграції сповіщень** зберігають публічний HTTPS-ендпоінт. Для тестової доставки задайте `IG_WEBHOOK_SECRET` у середовищі сервера. Запит передає синтетичну подію та заголовок `X-IdentityGuard-Signature`.

## Локальний стек Redpanda, ClickHouse і Temporal

```powershell
$env:IG_PORT = '8012'
docker compose -f deploy/compose/compose.yaml -f deploy/compose/platform.yaml up --build -d --wait
```

Якщо база порожня, заповніть її командою `make devdata` або `docker compose -f deploy/compose/compose.yaml -f deploy/compose/platform.yaml exec -T console python -m app.devdata seed`. На сторінці **Джерела даних** є фактичні лічильники черги, опублікованих повідомлень і подій ClickHouse. Нормалізовані записи передаються як Protobuf через Kafka API Redpanda. **Полювання** шукає й сортує індексовані події в ClickHouse за акаунтом, ідентичністю, операцією, регіоном, категорією та часом. Консоль під’єднується окремим користувачем із правом `SELECT`. Деталі знайдених подій і стан інцидентів зберігаються в операційній базі SQLite. Нові події стають доступними для пошуку після підтвердження запису в індекс.

Temporal автоматично оцінює накопичені події після закриття годинного вікна й 15-хвилинного періоду очікування. Ручне переоцінювання зі сторінки **Винятки** також виконує Temporal. У самостійному локальному запуску закриття вікон виконує фоновий цикл застосунку. Сторінка джерел показує межу останнього оцінювання. Сховище приватної області AWS відокремлене від цього демостека.

## Робота з оцінкою в інциденті

Відкрийте інцидент і перейдіть до блоку **Докази розрахунку ризику**. Там наведено значення й вагу кожного індикатора, його внесок у B, подію з максимальним сигналом, факти стану, пороги та порівняння з M = 1. Записи, створені до збереження доказів, отримують профіль і події-підстави після переоцінювання.

Compose публікує консоль лише на loopback. За потреби задайте приватний `IG_WORKSPACE_TOKEN` з принаймні 32 символів. `/healthz` перевіряє роботу HTTP-процесу, а `/readyz` перевіряє операційну базу та ClickHouse, якщо індекс увімкнено.

## Перевірки

```powershell
python -m uv sync --locked
python -m uv run --locked ruff check backend scripts
python -m uv run --locked ruff format --check backend scripts
python -m uv run --locked mypy
python -m uv run --locked pytest -q
$env:PYTHONPATH = 'backend'
python -m uv run --locked python scripts/export_contract.py --check
python -m uv run --locked python -m app.devdata evaluate
```

Оцінювання повертає код 1, якщо будь-який критерій §27.1 не виконано. Подробиці записуються в `reports/evaluation.md`.

Для браузерних тестів запустіть окрему демобазу. Сценарій реагування змінює стан тестового інциденту.

```powershell
$env:IG_E2E_URL = 'http://127.0.0.1:8013'
$env:IG_E2E_BROWSER = 'msedge'
npm --prefix frontend run test:e2e
```
