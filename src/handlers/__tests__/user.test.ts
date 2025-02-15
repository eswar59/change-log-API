import * as user from '../user'

describe('user handler', () => {
    it('should create new user', async () => {
        const req = {
            body: {
                username: 'hello',
                password: 'kind'
            }
        }
        const res = {
            json({ token }) {
                expect(token).toBeTruthy()
            }
        }
        await user.createNewUser(req,res,()=>{})
    })
})