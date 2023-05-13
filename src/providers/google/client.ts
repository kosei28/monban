export async function googleSignIn(endpoint: string) {
    location.href = `${endpoint}/signin/google`;
}
