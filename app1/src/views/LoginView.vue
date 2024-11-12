<template>
    <div class="login">
        <h1>Login to App 1</h1>
        <form @submit.prevent="handleLogin" class="login-form">
            <div class="form-group">
                <label for="email">Email</label>
                <input id="email" v-model="email" type="text" required>
            </div>

            <div class="form-group">
                <label for="password">Password</label>
                <input id="password" v-model="password" type="password" required>
            </div>

            <p v-if="error" class="error">{{ error }}</p>

            <button type="submit" :disabled="loading">
                {{ loading ? 'Logging in...' : 'Login' }}
            </button>
        </form>
    </div>
</template>

<script setup>
import { ref } from 'vue'
import { useAuthStore } from '../store'
import { useRouter } from 'vue-router'

const authStore = useAuthStore()
const router = useRouter()

const email = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

const handleLogin = async () => {
    loading.value = true
    error.value = ''

    try {
        const success = await authStore.login(email.value, password.value)
        if (success) {
            router.push('/home')
        } else {
            error.value = 'Invalid credentials'
        }
    } catch (e) {
        error.value = 'Login failed'
    } finally {
        loading.value = false
    }
}
</script>

<style scoped>
.login {
    max-width: 400px;
    margin: 2rem auto;
    padding: 2rem;
    border: 1px solid #ddd;
    border-radius: 8px;
}

.login-form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

input {
    padding: 0.5rem;
    border: 1px solid #ddd;
    border-radius: 4px;
}

button {
    padding: 0.5rem;
    background-color: #007bff;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}

button:disabled {
    background-color: #ccc;
}

.error {
    color: red;
}

.help {
    color: #666;
    font-size: 0.9rem;
    text-align: center;
}
</style>