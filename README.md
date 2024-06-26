# Test task BackDev
## Задание
### Используемые технологии:

- Go
- JWT
- MongoDB

### Задание:
Написать часть сервиса аутентификации.

Два REST маршрута:
- Первый маршрут выдает пару Access, Refresh токенов для пользователя сидентификатором (GUID) указанным в параметре запроса
- Второй маршрут выполняет Refresh операцию на пару Access, Refresh токенов

### Требования:
Access токен тип JWT, алгоритм SHA512, хранить в базе строго запрещено.

Refresh токен тип произвольный, формат передачи base64, хранится в базе исключительно в виде bcrypt хеша, должен быть защищен от изменения на стороне клиента и попыток повторного использования.

Access, Refresh токены обоюдно связаны, Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним.

## REST маршруты:
- **/auth?guid={_guid_}** - выдает пару Access, Refresh токенов для пользователя сидентификатором (GUID) указанным в параметре запроса
- **/refresh?guid={_guid_}** - выполняет Refresh операцию на пару Access, Refresh токенов.

## Соответствие требованиям:
- Access токен тип JWT, алгоритм SHA512;
- В Payload Access токена хранится guid пользователя и время, после которого истекает срок действия токена;
- Refresh токен тип произвольный. Состоит из двух частей: строки из 16 случайных символов и 8 последних символов Access токена, который был сгенерирован вместе с ним;
- В куки Refresh токен хранится в base64
- В БД Refresh токен хранится в виде bcrypt хеша
- После операции Refresh, Refresh токен в бд заменяется новым
- Refresh операцию для Access токена можно выполнить только тем Refresh токеном который был выдан вместе с ним. Это реализовано путём сравнения последних 8 символов у токенов.

## Примеры работы программы:

### Первый маршрут:

![image](https://github.com/ikarizxc/authentication-service/assets/114616603/aa953655-3c3e-42f6-972c-adfedfea599f)

![image](https://github.com/ikarizxc/authentication-service/assets/114616603/ccdc60e6-6821-4aa4-94fe-6c6a619591da)

### Второй маршрут:

![image](https://github.com/ikarizxc/authentication-service/assets/114616603/ea4623d8-53d1-4039-aba3-b116f662d528)

![image](https://github.com/ikarizxc/authentication-service/assets/114616603/d7b2cbf7-b535-4a2b-8cd1-8b79faae2ff0)

### Попытка операции Refresh для токенов, которые были выданы не вместе

![image](https://github.com/ikarizxc/authentication-service/assets/114616603/ee5bf6b8-100c-4bcd-8427-51af8aefa52c)

