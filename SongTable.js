import React, { useState, useEffect } from 'react';
import axios from 'axios'
import './styles.css';

const SongTable = ({ setInfo, Activity, setActivity, activeSong, setActiveSong }) => {
  const [songs, setSongs] = useState([]);
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get('http://localhost:8000/song_list');
        const jsonData = response.data;
        setSongs(jsonData)
      } catch(error){
        console.error("Get-request error", error);
      }
    };
    fetchData();
    console.log(songs)
 }, []);


  function clickHandler(song) {
    setActivity(!Activity);
    setActiveSong(song.id-1);
    setInfo(song.id-1);
  }
  return (
    <div className='custom-scrollbar'>
    <div className='tableBlock'>
      <h3>Tracks</h3>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Play</th>
            <th>Song Title</th>
            <th>Artist</th>
            <th>Album</th>
            <th>Duration</th>
            <th>Misc</th>
          </tr>
        </thead>
        <tbody>
          {songs.map(song => (
            <tr key={song.id}>
              <td className={activeSong === song.id-1 ? "active-song" : ""}>{song.id}</td>
              <td>
                <button className={`play-button${song.id}`} onClick={() => clickHandler(song)}>
                  {activeSong === song.id - 1 && Activity ? '❚❚' : '▶'}
                </button>
              </td>
              <td className={activeSong === song.id-1 ? "active-song" : ""}>{song.song_title}</td>
              <td>{song.song_author}</td>
              <td>{song.song_album}</td>
              <td>{song.song_duration}</td>
              <td>
                <button className='edit-button'>...</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
    </div>
  );
};

export default SongTable;
