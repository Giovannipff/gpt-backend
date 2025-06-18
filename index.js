// index.js

// 1. Carrega as variáveis de ambiente
require('dotenv').config();

// 2. Importa as bibliotecas
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const crypto = require('crypto'); // Para gerar códigos

// 3. Inicializa o Express
const app = express();
app.use(express.json()); // Permite que o Express entenda requisições com corpo JSON

// 4. Configura o Supabase Client (usando a service_role_key para segurança)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY; // A chave secreta

if (!supabaseUrl || !supabaseServiceRoleKey) {
    console.log(supabaseServiceRoleKey ? 'Chave de serviço carregada' : 'Chave de serviço NÃO carregada');
    console.error('Erro: Variáveis de ambiente SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY não configuradas.');
    process.exit(1); // Sai do processo se as chaves essenciais não estiverem lá
}

// Volte para a inicialização padrão. A service_role_key dará acesso ao auth.admin.
const supabase = createClient(supabaseUrl, supabaseServiceRoleKey);

// 5. Configura o Transporter de E-mail (Nodemailer)
const emailTransporter = nodemailer.createTransport({
    host: process.env.EMAIL_SERVICE_HOST,
    port: parseInt(process.env.EMAIL_SERVICE_PORT || '587'),
    secure: process.env.EMAIL_SERVICE_PORT === '465', // true para 465, false para outras como 587
    auth: {
        user: process.env.EMAIL_SERVICE_USER,
        pass: process.env.EMAIL_SERVICE_PASS,
    },
});

// 6. Middleware de Autenticação de API Key (para o Agente GPT)
const GPT_API_KEY = process.env.GPT_API_KEY;

if (!GPT_API_KEY) {
    console.warn('Atenção: GPT_API_KEY não configurada. As APIs estarão abertas!');
}

app.use((req, res, next) => {
    // Procura o cabeçalho Authorization
    const authHeader = req.headers['authorization'];

    if (GPT_API_KEY && (!authHeader || !authHeader.startsWith('Bearer '))) {
        return res.status(401).json({ error: 'Unauthorized', message: 'Bearer token ausente ou formato inválido.' });
    }

    const token = authHeader.split(' ')[1]; // Pega a parte do token após "Bearer "

    if (GPT_API_KEY && token !== GPT_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized', message: 'API Key inválida.' });
    }
    next(); // Se a chave for válida (ou não configurada), prossegue
});

// 7. Função para Gerar Código de Verificação
const generateVerificationCode = () => {
    // Gera um código alfanumérico de 6 caracteres (3 bytes -> 6 caracteres hex)
    return crypto.randomBytes(3).toString('hex').toUpperCase();
};

// --- ROTAS DA API ---

// API 1: Validar E-mail de Compra
app.post('/api/validar-email', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Missing email', details: 'O campo "email" é obrigatório.' });
    }

    try {
        // Chamada RPC para a função PostgreSQL que verifica a existência do usuário
        const { data: userExists, error } = await supabase.rpc('check_user_exists_by_email', { user_email: email });

        if (error) {
            console.error('Erro ao chamar RPC (check_user_exists_by_email):', error);
            return res.status(500).json({ error: 'Database error', details: error.message });
        }

        if (userExists) { // userExists será true ou false, conforme o retorno da função SQL
            return res.status(200).json({ isValid: true, message: 'Email encontrado e válido.' });
        } else {
            return res.status(200).json({ isValid: false, message: 'Email não encontrado em nossos registros de compra.' });
        }

    } catch (e) {
        console.error('Erro inesperado na validação de email:', e);
        res.status(500).json({ error: 'Server error', details: e.message });
    }
});

// API 2: Enviar Código de Verificação
app.post('/api/enviar-codigo-verificacao', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Missing email', details: 'O campo "email" é obrigatório.' });
    }

    try {
        // **PASSO CRÍTICO: RE-VALIDAR A EXISTÊNCIA DO E-MAIL NA BASE DE USUÁRIOS**
        // Chamada RPC para a função PostgreSQL que verifica a existência do usuário
        const { data: userExists, error: validationError } = await supabase.rpc('check_user_exists_by_email', { user_email: email });

        if (validationError) {
            console.error('Erro ao chamar RPC para validação de email em enviar-codigo:', validationError);
            return res.status(500).json({ error: 'Database error', details: validationError.message });
        }

        // Se o e-mail NÃO existe na tabela auth.users, retorne erro e NÃO envie e-mail
        if (!userExists) {
            console.log(`[DEBUG] Email "${email}" não encontrado na base de usuários. Não enviando código.`);
            return res.status(400).json({ success: false, message: 'Não é possível enviar código. Email não encontrado em nossos registros.' });
        }

        // Se o e-mail existe, prossiga com a geração e envio do código
        console.log(`[DEBUG] Email "${email}" encontrado. Gerando e enviando código.`);

        const verificationCode = generateVerificationCode();
        const expiryTime = new Date(Date.now() + 10 * 60 * 1000); // Código válido por 10 minutos

        // Salva/Atualiza o código no Supabase
        const { error: dbError } = await supabase
            .from('codigos_verificacao')
            .upsert({ email: email, code: verificationCode, expires_at: expiryTime.toISOString() }, { onConflict: 'email' });

        if (dbError) {
            console.error('Erro ao salvar código no Supabase:', dbError);
            return res.status(500).json({ error: 'Database error', details: dbError.message });
        }

        // Envia o e-mail
        await emailTransporter.sendMail({
            from: process.env.EMAIL_FROM_ADDRESS,
            to: email,
            subject: 'Seu Código de Verificação de Compra',
            text: `Seu código de verificação é: ${verificationCode}. Ele é válido por 10 minutos.`,
            html: `<p>Seu código de verificação para sua compra é: <strong>${verificationCode}</strong>.</p><p>Ele é válido por 10 minutos.</p>`
        });

        res.status(200).json({ success: true, message: 'Código de verificação enviado com sucesso.' });

    } catch (e) {
        console.error('Erro inesperado ao enviar código de verificação:', e);
        res.status(500).json({ error: 'Server error', details: e.message });
    }
});

// API 3: Verificar Código de Verificação
app.post('/api/verificar-codigo', async (req, res) => {
    const { email, codigo } = req.body;

    if (!email || !codigo) {
        return res.status(400).json({ error: 'Missing parameters', details: 'Os campos "email" e "codigo" são obrigatórios.' });
    }

    try {
        const { data, error } = await supabase
            .from('codigos_verificacao')
            .select('code, expires_at')
            .eq('email', email)
            .single();

        if (error && error.code !== 'PGRST116') {
            console.error('Erro ao consultar Supabase para código:', error);
            return res.status(500).json({ error: 'Database error', details: error.message });
        }

        // Se não houver dados, ou o código expirou
        if (!data || new Date(data.expires_at) < new Date()) {
            return res.status(200).json({ isCorrect: false, message: 'Código de verificação incorreto ou expirado.' });
        }

        // Compara o código (case-insensitive para robustez)
        if (data.code.toUpperCase() === codigo.toUpperCase()) {
            // Opcional: remover o código do Supabase após verificação bem-sucedida para evitar reuso
            await supabase.from('codigos_verificacao').delete().eq('email', email);
            return res.status(200).json({ isCorrect: true, message: 'Código de verificação correto.' });
        } else {
            return res.status(200).json({ isCorrect: false, message: 'Código de verificação incorreto.' });
        }

    } catch (e) {
        console.error('Erro inesperado na verificação do código:', e);
        res.status(500).json({ error: 'Server error', details: e.message });
    }
});

// 8. Inicia o Servidor


// Rota para o Agente GPT acessar o esquema OpenAPI
// (Você pode criar um arquivo openapi.yaml e servi-lo estaticamente ou gerá-lo aqui)
// Para este exemplo, vamos retornar um JSON básico, você pode adaptá-lo para YAML se preferir.
app.get('/openapi.json', (req, res) => {
    const publicBackendUrl = "https://gpt-backend-navy.vercel.app"; // Sua URL Vercel
    const openApiSchema = {
        openapi: '3.1.0',
        info: {
            title: 'API de Verificação de Compras',
            version: '1.0.0',
            description: 'API para validar e-mails de compra e gerenciar códigos de verificação.'
        },
        servers: [
            {
                url: publicBackendUrl // <-- AGORA USANDO A URL PÚBLICA DA VERCEL
            }
        ],
        paths: {
            '/api/validar-email': {
                post: {
                    operationId: 'validarEmailDeCompra',
                    summary: 'Valida um email de compra no Supabase.',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        email: { type: 'string', format: 'email', description: 'O email de compra a ser validado.' }
                                    },
                                    required: ['email']
                                }
                            }
                        }
                    },
                    responses: {
                        '200': { description: 'Resposta da validação do email.' },
                        '400': { description: 'Requisição inválida.' },
                        '401': { description: 'Não autorizado (API Key inválida).' },
                        '500': { description: 'Erro interno do servidor.' }
                    }
                }
            },
            '/api/enviar-codigo-verificacao': {
                post: {
                    operationId: 'enviarCodigoDeVerificacao',
                    summary: 'Envia um código de verificação para o email fornecido.',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        email: { type: 'string', format: 'email', description: 'O email para o qual o código será enviado.' }
                                    },
                                    required: ['email']
                                }
                            }
                        }
                    },
                    responses: {
                        '200': { description: 'Confirmação de envio do código.' },
                        '400': { description: 'Requisição inválida.' },
                        '401': { description: 'Não autorizado (API Key inválida).' },
                        '500': { description: 'Erro interno do servidor.' }
                    }
                }
            },
            '/api/verificar-codigo': {
                post: {
                    operationId: 'verificarCodigo',
                    summary: 'Verifica se o código digitado corresponde ao email.',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        email: { type: 'string', format: 'email', description: 'O email do usuário.' },
                                        codigo: { type: 'string', description: 'O código de verificação digitado.' }
                                    },
                                    required: ['email', 'codigo']
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "200": { "description": "Resultado da verificação do código." },
                    "400": { "description": "Requisição inválida." },
                    "401": { "description": "Não autorizado (API Key inválida)." },
                    "500": { "description": "Erro interno do servidor." }
                }
            }
        },
        "components": {
            "schemas": {}, // <-- SEÇÃO 'SCHEMAS' ADICIONADA E VAZIA AQUI!
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "Autenticação usando um Bearer token (API Key do GPT)."
                }
            }
        },
        "security": [
            {
                "BearerAuth": []
            }
        ]
    };
    res.json(openApiSchema);
});