import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

import api from '../../../utils/api'

import RoundedImage from '../../layout/RoundedImage'
import styles from './Dashboard.module.css'

/* hooks */
import useFlashMessage from '../../../hooks/useFlashMessage'

function MyPets() {
  const [pets, setPets] = useState([])
  const [token] = useState(localStorage.getItem('token') || '')
  const { setFlashMessage } = useFlashMessage()

  useEffect(() => {
    async function fetchData() {
      const { data } = await api.get('/pets/mypets', {
        headers: {
          Authorization: `Bearer ${JSON.parse(token)}`
        }
      })
      setPets(data.pets)
    }
    fetchData().catch(console.error);
  }, [token])

  async function removePet(id) {
    let msgType = 'success'
    let msgText

    try {
      const { data } = await api.delete(`/pets/${id}`, {
        headers: {
          Authorization: `Bearer ${JSON.parse(token)}`
        }
      })
      const updatedPets = pets.filter(pet => pet._id !== id)
      setPets(updatedPets)
      msgText = data.message
    } catch (error) {
      msgType = 'error'
      msgText = error.response.data.message
    }

    setFlashMessage(msgText, msgType)
  }

  return (
    <section>
      <div className={styles.petlist_header}>
        <h1>MyPets</h1>
        <Link to="/pet/add">Cadastrar Pet</Link>
      </div>
      <div className={styles.petlist_container}>
        {pets.length > 0 &&
          pets.map(pet => (
            <div key={pet._id} className={styles.petlist_row}>
              <RoundedImage
                src={`${process.env.REACT_APP_API}/images/pets/${pet.images[0]}`}
                alt={pet.name}
                width='px75'
              />
              <span className='bold'>{pet.name}</span>
              <div className={styles.actions}>
                {pet.available ? (
                  <>
                    {pet.adopter && <button className={styles.conclude_btn}>Concluir adoção</button>}
                    <Link to={`/pet/edit/${pet._id}`}>Editar</Link>
                    <button onClick={() => removePet(pet._id)}>Excluir</button>
                  </>
                ) : (
                  <p>Pet já adotado</p>
                )}
              </div>
            </div>
          ))
        }
        {pets.length === 0 && <p>Não há Pets cadastrados</p>}
      </div>
    </section>
  )
}

export default MyPets