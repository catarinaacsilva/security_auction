# Security P1G1

## Sumário
Nesta pasta encontra-se o código do projeto segurança.

##Estrutura
```
Root
│   bin
│   src    
│   README.md
```

## Base de Dados

### Auction Manager

#### Tabela para mapear leilões a utilizadores (auctions)

|  Columns   |       Types      |
|------------|------------------|
| cc         | **TEXT (PK)**    |
| auction_id | **INTEGER (PK)** |

#### Tabela para armazenar as chaves dos clientes (bids)

|  Columns   |         Types       |
|------------|---------------------|
| auction_id | **INTEGER (PK/FK)** |
| sequence   | **INTEGER (PK)**    |
| identity   | TEXT                |
| secret     | TEXT                |

#### Tabela para armazenar o código dinamico (codes)

|  Columns   |         Types       |
|------------|---------------------|
| auction_id | **INTEGER (PK/FK)** |
| code       | TEXT                |

### Auction Repository

#### Tabela para armazenar os leilões (auctions)

| Columns  |       Types      |
|----------|------------------|
| id       | **INTEGER (PK)** |
| title    | TEXT             |
| desc     | TEXT             |
| type     | INTEGER          |
| subtype  | INTEGER          |
| duration | INTEGER          |
| start    | TIMESTAMP        |
| stop     | TIMESTAMP        |
| seed     | TEXT             |
| open     | INTEGER (1)      |
| claimed  | INTEGER (0)      |

#### Tabela para armazenar as apostas (bids)

|   Columns   |       Types      |
|-------------|------------------|
| auction_id  | **INTEGER (PK/FK)** |
| sequence    | **INTEGER (PK)** |
| prev_hash   | TEXT             |
| identity    | TEXT             |
| value       | TEXT             |

#### Tabela para armazenar as chaves das bids (secrets)

|   Columns   |         Types       |
|-------------|---------------------|
| auction_id  | **INTEGER (PK/FK)** |
| sequence    | **INTEGER (PK/FK)** |
| secret      | TEXT                |


#### Tabela para armazenar os vencedores (winners)

|   Columns   |       Types      |
|-------------|------------------|
| auction_id  | **INTEGER (PK)** |
| sequence    | INTEGER (FK)     |

## Pré-requisitos
Os pré-requisitos podem ser instalados manualmente.
Dentro da pasta src:

```
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```
Ou através de um script que prepara e executa o projecto:

```
$ ./bin/build_run.sh
```

## Executar

### Manualmente
Abrir 3 terminais e em cada terminal correr apenas uma vez:
```
$ source venv/bin/activate
```

Execute as aplicações pela seguinte ordem:

Terminal 1:
```
$ python3 -m src.auction_repository.auction_repository
```

Terminal 2:
```
$ python3 -m src.auction_manager.auction_manager
```

Terminal 3:
```
$ python3 -m src.client.client
```
### Automaticamente
Foram criados 3 scripts em bash para facilitar a execução dos 3 processos.
Os scripts encontram-se na pasta bin e cada um deles ativa o virtual environment e executa o respetivo processo.
Basta executa-los pela seguinte ordem (em terminais diferentes):
1. ./bin/auction_repository.sh
2. ./bin/auction_manager.sh
3. ./bin/client.sh

Em alternativa basta executar apenas o script ./bin/build_run.sh

