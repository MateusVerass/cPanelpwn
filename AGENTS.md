# Convenções do projeto

## Idioma: PT-BR permanente

**Todo o código, comentários, docstrings, help do CLI, mensagens de log,
reportes (HTML/CSV/JSON), testes e documentação devem estar em português
brasileiro (PT-BR).**

- Nunca escrever em espanhol (archivo, fuente, puerto, acción, etc.) nem em
  inglês (file, source, port, action, etc.) para texto destinado ao usuário.
- Palavras técnicas universais ficam como estão — payload, token, header,
  endpoint, WAF, DNS, etc. são gíria técnica, não prosa.
- Nomes de flags, variáveis, funções e identificadores permanecem em inglês
  (código é código); só os textos legíveis mudam.
- Antes de terminar uma edição, verificar com:
  `grep -rnE "ñ|ción|archivo|fuente|puerto|acción|versión|Usage:|Error:" cpanelpwn/ tests/ README.md`

## Stack

- Só stdlib Python (3.8+). Nada de dependências externas.
- Não commitar nada sem pedido explícito do usuário.